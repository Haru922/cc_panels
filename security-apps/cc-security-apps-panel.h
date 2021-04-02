/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/*
 * Copyright (C) 2020 gooroom <gooroom@gooroom.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <shell/cc-panel.h>
#include <webkit2/webkit2.h>
#include <lsf/lsf-main.h>
#include <lsf/lsf-util.h>
#include <lsf/lsf-auth.h>
#include <lsf/lsf-dbus.h>

G_BEGIN_DECLS

#define CC_TYPE_SECURITY_APPS_PANEL (cc_security_apps_panel_get_type ())
G_DECLARE_FINAL_TYPE (CcSecurityAppsPanel, cc_security_apps_panel, CC, SECURITY_APPS_PANEL, CcPanel)

#define LSF_CC_PANEL_DIR "/var/tmp/lsf/lsf-cc-panel"
#define LSF_API          "/usr/lib/x86_64-linux-gnu/liblsf.so"
#define CC_PASSPHRASE    "n6x6myibEAvfN9vIDDPQi+iCoE7yTuHP//eC195+g7w="
#define SECURITY_APPS_MAX 1000

#define SECURITY_APPS_UI "/org/gnome/control-center/security-apps/security-apps.ui"

#define CC_DBUS_NAME     "kr.gooroom.controlcenter"

#define FREE(v) \
    if (v) { \
      free(v); \
      v=NULL; \
    }

gchar *lsf_panel_symm_key;
gchar *lsf_panel_access_token;

GtkWidget *cc_security_apps_panel_new (void);

G_END_DECLS
