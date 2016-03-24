/*
 * Network Configuration Module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 * This file declares wifi direct manager dbus error functions.
 *
 * @file        wifi-direct-error.h
 * @author      Nishant Chaprana (n.chaprana@samsung.com)
 * @version     0.1
 */

#ifndef __WIFI_DIRECT_ERROR_H__
#define __WIFI_DIRECT_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <tizen.h>
#include <wifi-direct.h>

#define WFD_MANAGER_ERROR_INTERFACE WFD_MANAGER_SERVICE ".Error"

void wfd_error_set_gerror(wifi_direct_error_e error_code, GError **error);
void wfd_error_register(void);
void wfd_error_deregister(void);

#ifdef __cplusplus
}
#endif

#endif /* __WIFI_DIRECT_ERROR_H__ */
