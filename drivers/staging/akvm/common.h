#ifndef _AKVM_COMMON_H_
#define _AKVM_COMMON_H_

#define __FUNC_TRACE__(text) pr_info("%s() " #text "\n", __func__);
#define FUNC_ENTRY()  __FUNC_TRACE__("ENTRY")
#define FUNC_EXIT()  __FUNC_TRACE__("EXIT")



#endif
