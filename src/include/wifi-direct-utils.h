/*
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved 
 *
 * This file is part of <Wi-Fi Direct>
 * Written by Sungsik Jang<sngsik.jang@samsung.com>, Dongwook Lee<dwmax.lee@samsung.com>
 *
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall use it only in accordance
 * with the terms of the license agreement you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability of the software,
 * either express or implied, including but not limited to the implied warranties of merchantability,
 * fitness for a particular purpose, or non-infringement.
 * SAMSUNG shall not be liable for any damages suffered by licensee as a result of using,
 * modifying or distributing this software or its derivatives.
 *
 */



#ifndef __WIFI_DIRECT_UTILS_H_ 
#define __WIFI_DIRECT_UTILS_H_

/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Functions
 *****************************************************************************/

int wfd_macaddr_atoe(char *p, unsigned char mac[]);

/*****************************************************************************
 * 	Macros
 *****************************************************************************/


#ifdef VITA_FEATURE
#include <dlog.h>

#define WIFI_DIRECT_SERVER_MID		"wfd-server"

#define WFD_LOG_LOW 	LOG_VERBOSE
#define WFD_LOG_HIGH 	LOG_INFO
#define WFD_LOG_ERROR 	LOG_ERROR
#define WFD_LOG_WARN 	LOG_WARN
#define WFD_LOG_ASSERT 	LOG_FATAL
#define WFD_LOG_EXCEPTION 	LOG_FATAL

char * wfd_debug_print(char* file, int line, char* format, ...);
char * wfd_trimming_path(const char* filewithpath);

char * wfd_trim_path(const char* filewithpath);
int wfd_gettid();

#define WFD_SERVER_LOG(log_level, format, args...) \
	LOG(log_level, WIFI_DIRECT_SERVER_MID, "[%s:%04d,%d] " format, wfd_trim_path(__FILE__), __LINE__,wfd_gettid(),##args)
#define __WFD_SERVER_FUNC_ENTER__	LOG(LOG_VERBOSE,  WIFI_DIRECT_SERVER_MID, "[%s:%04d,%d] Enter: %s()\n", wfd_trim_path(__FILE__), __LINE__,wfd_gettid(),__func__)
#define __WFD_SERVER_FUNC_EXIT__	LOG(LOG_VERBOSE,  WIFI_DIRECT_SERVER_MID, "[%s:%04d,%d] Quit: %s()\n", wfd_trim_path(__FILE__), __LINE__,wfd_gettid(),__func__)

#else /** _DLOG_UTIL */

#define WFD_SERVER_LOG(log_level, format, args...) printf("[%s:%04d,%d] " format, wfd_trim_path(__FILE__), __LINE__,wfd_gettid(), ##args)
#define __WFD_SERVER_FUNC_ENTER__	printf("[%s:%04d,%d] Entering: %s()\n", wfd_trim_path(__FILE__), __LINE__,wfd_gettid(),__func__)
#define __WFD_SERVER_FUNC_EXIT__	printf("[%s:%04d,%d] Quit: %s()\n", wfd_trim_path(__FILE__), __LINE__,wfd_gettid(),__func__)

#endif /** _USE_DLOG_UTIL */


#endif /** __WIFI_DIRECT_UTILS_H_ */

