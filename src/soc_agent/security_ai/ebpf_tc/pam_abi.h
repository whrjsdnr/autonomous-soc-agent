/* Linux-PAM stable public ABI subset. System runtime libraries are linked; no
 * vendored PAM implementation. Declarations verified against Linux-PAM headers.
 * The build host lacks libpam development headers. Never call in B-2A. */
#ifndef SOC_PAM_ABI_H
#define SOC_PAM_ABI_H
struct pam_handle;typedef struct pam_handle pam_handle_t;
struct pam_message {int msg_style;const char *msg;};
struct pam_response {char *resp;int resp_retcode;};
struct pam_conv {int (*conv)(int,const struct pam_message **,struct pam_response **,void *);void *appdata_ptr;};
extern int pam_start(const char *,const char *,const struct pam_conv *,pam_handle_t **);
extern int pam_authenticate(pam_handle_t *,int);
extern int pam_acct_mgmt(pam_handle_t *,int);
extern int pam_end(pam_handle_t *,int);
extern int misc_conv(int,const struct pam_message **,struct pam_response **,void *);
#define PAM_SUCCESS 0
#define PAM_CONV_ERR 19
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_TEXT_INFO 4
#define PAM_ERROR_MSG 3
#define PAM_DISALLOW_NULL_AUTHTOK 1
#endif
