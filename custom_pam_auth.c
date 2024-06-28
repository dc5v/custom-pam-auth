#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <unistd.h>

#define HASH_TYPE_SHA256 "sha256"
#define HASH_TYPE_SHA512 "sha512"
#define HASH_TYPE_MD5 "md5"
#define HASH_TYPE_PLAIN "plain"
#define HASH_TYPE_TEXT "text"
#define HASH_TYPE_PAM "pam"
#define HASH_TYPE_PAM_UNIX "unix"

#define CONF_HASHTYPE "hashtype"
#define CONF_PASSWORD "password"
#define CONF_ENABLED "enabled"

#define DEFAULT_HASHTYPE HASH_TYPE_SHA256
#define DEFAULT_CONFIG_FILENAME ".custom-auth"

const char *get_param(int argc, const char **argv, const char *param)
{
  for (int i = 0; i < argc; ++i)
  {
    if (strncasecmp(argv[i], param, strlen(param)) == 0)
    {
      return argv[i] + strlen(param) + 1;
    }
  }
  return NULL;
}

void trim(char *str)
{
  char *end;

  while (isspace((unsigned char)*str))
  {
    str++;
  }

  if (*str == 0)
  {
    return;
  }

  end = str + strlen(str) - 1;

  while (end > str && isspace((unsigned char)*end))
  {
    end--;
  }

  end[1] = '\0';
}

int read_conf(const char *filename, char *hash_type, char *stored_hash, int *enabled)
{
  FILE *file = fopen(filename, "r");
  if (!file)
  {
    return -1;
  }

  char line[256];
  while (fgets(line, sizeof(line), file))
  {
    char *comment = strchr(line, '#');

    if (comment)
    {
      *comment = '\0';
    }

    trim(line);

    if (strlen(line) == 0)
    {
      continue;
    }

    if (strncasecmp(line, CONF_HASHTYPE "=", strlen(CONF_HASHTYPE) + 1) == 0)
    {
      strncpy(hash_type, line + strlen(CONF_HASHTYPE) + 1, 64);
      hash_type[63] = '\0';

      continue;
    }

    if (strncasecmp(line, CONF_PASSWORD "=", strlen(CONF_PASSWORD) + 1) == 0)
    {
      strncpy(stored_hash, line + strlen(CONF_PASSWORD) + 1, 128);
      stored_hash[127] = '\0';

      continue;
    }

    if (strncasecmp(line, CONF_ENABLED "=", strlen(CONF_ENABLED) + 1) == 0)
    {
      char enable_value[8];

      strncpy(enable_value, line + strlen(CONF_ENABLED) + 1, 8);
      enable_value[7] = '\0';

      if (strncasecmp(enable_value, "false", 5) == 0)
      {
        *enabled = 0;
      }
    }
  }

  fclose(file);
  return 0;
}

int check_hashtype(const char *hash_type)
{
  const char *valid_hash_types[] = {HASH_TYPE_SHA256, HASH_TYPE_SHA512, HASH_TYPE_MD5, HASH_TYPE_PLAIN, HASH_TYPE_TEXT, HASH_TYPE_PAM, HASH_TYPE_PAM_UNIX, NULL};

  for (int i = 0; valid_hash_types[i] != NULL; ++i)
  {
    if (strcasecmp(hash_type, valid_hash_types[i]) == 0)
    {
      return 1;
    }
  }

  return 0;
}

void check_hash(const char *str, const char *hash_type, char *output_buffer)
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;

  mdctx = EVP_MD_CTX_new();

  if (mdctx == NULL)
  {
    syslog(LOG_ERR, "Can not create EVP_MD_CTX");
    return;
  }

  if (strcasecmp(hash_type, HASH_TYPE_SHA256) == 0)
  {
    md = EVP_sha256();
  }
  else if (strcasecmp(hash_type, HASH_TYPE_SHA512) == 0)
  {
    md = EVP_sha512();
  }
  else if (strcasecmp(hash_type, HASH_TYPE_MD5) == 0)
  {
    md = EVP_md5();
  }
  else
  {
    md = EVP_sha256();
  }

  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, str, strlen(str));
  EVP_DigestFinal_ex(mdctx, hash, &hash_len);
  EVP_MD_CTX_free(mdctx);

  for (unsigned int i = 0; i < hash_len; ++i)
  {
    sprintf(output_buffer + (i * 2), "%02x", hash[i]);
  }

  output_buffer[hash_len * 2] = 0;
}

int pam_authenticate_with_pam_unix(const char *user, const char *password)
{
  pam_handle_t *pamh = NULL;

  struct pam_conv pam_conversation = {.conv = NULL, .appdata_ptr = NULL};
  int retval;

  retval = pam_start("common-auth", user, &pam_conversation, &pamh);
  if (retval != PAM_SUCCESS)
  {
    return retval;
  }

  retval = pam_set_item(pamh, PAM_AUTHTOK, password);
  if (retval != PAM_SUCCESS)
  {
    pam_end(pamh, retval);
    return retval;
  }

  retval = pam_authenticate(pamh, 0);
  pam_end(pamh, retval);

  return retval;
}

int converse(pam_handle_t *pamh, int nargs, const struct pam_message **message, struct pam_response **response)
{
  int retval;
  struct pam_conv *conv;

  retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (retval != PAM_SUCCESS)
  {
    return retval;
  }

  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

/**
 * USAGE:
 *
 * auth    required    pam_auth_module.so filename=config hashtype=sha256
 * ... account required    pam_unix.so
 * ... auth    required    pam_unix.so
 */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *user;
  const char *password;
  const char *config_file;

  char config_path[512];
  char stored_hash[128];
  char input_hash[128];
  char hash_type[64] = {0};

  int enabled = 1;

  pam_get_item(pamh, PAM_USER, (const void **)&user);

  config_file = get_param(argc, argv, "filename=");

  if (!config_file)
  {
    snprintf(config_path, sizeof(config_path), "%s/%s", getpwuid(getuid())->pw_dir, DEFAULT_CONFIG_FILENAME);
  }
  else
  {
    struct passwd *pw = getpwnam(user);

    if (!pw)
    {
      return PAM_AUTH_ERR;
    }
    snprintf(config_path, sizeof(config_path), "%s/%s", pw->pw_dir, config_file);
  }

  if (read_conf(config_path, hash_type, stored_hash, &enabled) != 0 || !enabled)
  {
    return PAM_AUTH_ERR;
  }

  const char *param_hash_type = get_param(argc, argv, "hashtype=");

  if (param_hash_type && check_hashtype(param_hash_type))
  {
    strncpy(hash_type, param_hash_type, sizeof(hash_type) - 1);
    hash_type[sizeof(hash_type) - 1] = '\0';
  }
  else if (!check_hashtype(hash_type))
  {
    strcpy(hash_type, DEFAULT_HASHTYPE);
  }

  struct pam_message msg = {.msg_style = PAM_PROMPT_ECHO_OFF, .msg = "Password: "};
  const struct pam_message *msgp = &msg;
  struct pam_response *resp = NULL;

  int ret = converse(pamh, 1, &msgp, &resp);

  if (ret != PAM_SUCCESS || resp == NULL)
  {
    return PAM_CONV_ERR;
  }

  password = resp->resp;

  if (strcasecmp(hash_type, HASH_TYPE_PAM) == 0)
  {
    int retval = pam_authenticate_with_pam_unix(user, password);

    memset(resp->resp, 0, strlen(resp->resp));
    free(resp->resp);
    free(resp);

    return retval == PAM_SUCCESS ? PAM_SUCCESS : PAM_AUTH_ERR;
  }

  check_hash(password, hash_type, input_hash);

  memset(resp->resp, 0, strlen(resp->resp));
  
  free(resp->resp);
  free(resp);

  if (strcmp(stored_hash, input_hash) != 0)
  {
    return PAM_AUTH_ERR;
  }

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
