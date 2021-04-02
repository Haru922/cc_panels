/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/*
 * Copyright (C) 2020 gooroom <gooroom@gooroom.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * * This program is distributed in the hope that it will be useful, * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <shell/cc-panel.h>
#include <lsf/lsf-main.h>
#include <lsf/lsf-util.h>
#include <lsf/lsf-auth.h>
#include <lsf/lsf-dbus.h>

G_BEGIN_DECLS

#define CC_TYPE_SECURITY_FRAMEWORK_PANEL (cc_security_framework_panel_get_type ())
G_DECLARE_FINAL_TYPE (CcSecurityFrameworkPanel, cc_security_framework_panel, CC, SECURITY_FRAMEWORK_PANEL, CcPanel)

#define APPS_MAX               99

#define LSF_PAGE                1
#define LSF_NOT_FOUND_PAGE      0

#define RADIUS_SMALL            3
#define RADIUS_MEDIUM           4
#define RADIUS_LARGE            6

#define XPOS                    0
#define YPOS                    1

#define VT                     15
#define HT                     20

#define STARTING_BLINK_CNT      5
#define ENDING_BLINK_CNT       15
#define MOVING_CNT              6
#define KEY_EXCHANGE_FIN        3

#define SCENE_CNT              17
#define SCENE_END              -1

#define DEFAULT_BUF_SIZE     4096
#define PARAM_BUF            1024

#define NORM                    0
#define REV                     1
#define LOG_BUF                10
#define PRESENTER_TIMEOUT      50
#define MINUTE              60000
#define UPDATER_TIMEOUT  1*MINUTE

#define RESOURCE_DIR     "/org/gnome/control-center/security-framework/resources"
#define CC_IMG           RESOURCE_DIR"/cc-image.svg"
#define GHUB_IMG         RESOURCE_DIR"/ghub-image.svg"
#define GAUTH_IMG        RESOURCE_DIR"/gauth-image.svg"
#define GCTRL_IMG        RESOURCE_DIR"/gctrl-image.svg"
#define AGENT_IMG        RESOURCE_DIR"/agent-image.svg"
#define GPMS_IMG         RESOURCE_DIR"/gpms-image.svg"
#define APPS_IMG         RESOURCE_DIR"/apps-image.svg"

#define CC_DBUS          "kr.gooroom.controlcenter"
#define GHUB_DBUS        "kr.gooroom.ghub"
#define GAUTH_DBUS       "kr.gooroom.gauth"
#define GCTRL_DBUS       "kr.gooroom.gcontroller"
#define AGENT_DBUS       "kr.gooroom.agent"

#define GPMS_NAME        "gpms"
#define LOG_DIRECTORY    "/var/log/lsf/"
#define LOG_FILE_PREFIX  "message"

#define LSF_CONF         "/etc/gooroom/lsf/lsf.conf"
#define GCSR_CONF        "/etc/gooroom/gooroom-client-server-register/gcsr.conf"
#define V3_DOMAIN        "http://localhost:88"

#define CC_PASSPHRASE      "n6x6myibEAvfN9vIDDPQi+iCoE7yTuHP//eC195+g7w="

gchar *lsf_panel_symm_key;
gchar *lsf_panel_access_token;

enum
{
  SCENE_IDLE,
  SCENE_METHOD_CALL,
  SCENE_METHOD_CALL_REV,
  SCENE_POLICY_RELOAD,
  SCENE_NUM
};

enum
{
  CC,
  GHUB,
  GAUTH,
  GCTRL,
  AGENT,
  GPMS,
  APPS,
  CELL_NUM
};

char *module_name[CELL_NUM] = { "CC",
                                "GHUB",
                                "GAUTH",
                                "GCTRL",
                                "AGENT",
                                "GPMS",
                                "APPS" };

char *lsf_dbus_name[] = { "kr.gooroom.controlcenter",
                          "kr.gooroom.ghub",
                          "kr.gooroom.gauth",
                          "kr.gooroom.gcontroller",
                          "kr.gooroom.agent" };

enum
{
  DIRECTION_GHUB_CC,
  DIRECTION_GHUB_GAUTH,
  DIRECTION_GHUB_AGENT,
  DIRECTION_GHUB_GCTRL,
  DIRECTION_AGENT_GPMS,
  DIRECTION_GHUB_APPS,
  DIRECTION_NUM
};

enum
{
  COLOR_NONE,
  COLOR_RED,
  COLOR_GREEN,
  COLOR_BLUE,
  COLOR_YELLOW,
  COLOR_BLACK,
  COLOR_NUM
};

enum
{
  GET_CONFIG,
  SET_CONFIG,
  UNSET_CONFIG,
  LAUNCH_AGENT,
  KILL_AGENT,
  LAUNCH_APP,
  KILL_APP,
  GET_STATUS,
  NUM_DBUS_ARGS
};

enum
{
  DMSG_SEQ,
  DMSG_DIRECTION,
  DMSG_METHOD,
  DMSG_ABS,
  DMSG_GLYPH,
  DMSG_FROM,
  DMSG_TO,
  DMSG_FUNC,
  DMSG_ERR,
  DMSG_PAYLOAD,
  DMSG_NUM
};

enum
{
  SOURCE_FUNC_PRESENTER,
  SOURCE_FUNC_UPDATER,
  SOURCE_FUNC_NUM
};

typedef struct _security_app
{
  GtkWidget *app_menu;
  GtkWidget *app_button;
  gchar     *dbus_name;
  gchar     *display_name;
  gboolean   exe_stat;
  gboolean   auth_stat;
  gboolean   set;
  int        cell_ref;
  int        app_idx;
} security_app;

GtkWidget *cc_security_framework_panel_new (void);

G_END_DECLS
