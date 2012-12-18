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

#ifdef USE_DLOG
#include <dlog.h>

#undef LOG_TAG
#define LOG_TAG "WIFI_DIRECT_MANAGER"

#define WDS_LOGV(format, args...) LOGV(format, ##args)
#define WDS_LOGD(format, args...) LOGD(format, ##args)
#define WDS_LOGI(format, args...) LOGI(format, ##args)
#define WDS_LOGW(format, args...) LOGW(format, ##args)
#define WDS_LOGE(format, args...) LOGE(format, ##args)
#define WDS_LOGF(format, args...) LOGF(format, ##args)

#define __WDS_LOG_FUNC_ENTER__ LOGV("Enter")
#define __WDS_LOG_FUNC_EXIT__ LOGV("Quit")

#else /** _DLOG_UTIL */

#define WDS_LOGV(format, args...) \
	printf("[V/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#define WDS_LOGD(format, args...) \
	printf("[D/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#define WDS_LOGI(format, args...) \
	printf("[I/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#define WDS_LOGW(format, args...) \
	printf("[W/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#define WDS_LOGE(format, args...) \
	printf("[E/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#define WDS_LOGF(format, args...) \
	printf("[F/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> "format, __FILE__, __FUNCTION__, __LINE__, ##args)

#define __WDS_LOG_FUNC_ENTER__ \
	printf("[V/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> Enter", __FILE__, __FUNCTION__, __LINE__)
#define __WDS_LOG_FUNC_EXIT__ \
	printf("[V/WIFI_DIRECT_MANAGER] %s: %s()(%4d)> Exit", __FILE__, __FUNCTION__, __LINE__)

#endif /** _DLOG_UTIL */

#endif /** __WIFI_DIRECT_UTILS_H_ */
