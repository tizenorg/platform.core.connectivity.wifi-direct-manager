/*
 * Network Configuration Module
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * This file declares macros for logging.
 *
 * @file	wifi-direct-log.h
 * @author	Nishant Chaprana (n.chaprana@samsung.com)
 * @version	0.1
 */

#ifndef __WIFI_DIRECT_LOG_H__
#define __WIFI_DIRECT_LOG_H__

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

#define __WDS_LOG_FUNC_ENTER__ LOGD("Enter")
#define __WDS_LOG_FUNC_EXIT__ LOGD("Quit")

#define WDS_SECLOGI(format, args...) SECURE_LOG(LOG_INFO, LOG_TAG, format, ##args)
#define WDS_SECLOGD(format, args...) SECURE_LOG(LOG_DEBUG, LOG_TAG, format, ##args)

#else /* USE_DLOG */

#define WDS_LOGV(format, args...)
#define WDS_LOGD(format, args...)
#define WDS_LOGI(format, args...)
#define WDS_LOGW(format, args...)
#define WDS_LOGE(format, args...)
#define WDS_LOGF(format, args...)

#define __WDS_LOG_FUNC_ENTER__
#define __WDS_LOG_FUNC_EXIT__

#define WDS_SECLOGI(format, args...)
#define WDS_SECLOGD(format, args...)

#endif /* USE_DLOG */
#endif /* __WIFI_DIRECT_LOG_H__ */
