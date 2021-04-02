/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/*
 *
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

#include <config.h>
#include <math.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <glib/gi18n.h>

#include "cc-security-framework-panel.h"
#include "cc-security-framework-resources.h"

#define SECURITY_FRAMEWORK_SCHEMA "org.gnome.desktop.security-framework"

struct _CcSecurityFrameworkPanel
{
  CcPanel    parent_instance;
  GtkWidget *app_button[APPS_MAX];
  GtkWidget *app_menu[APPS_MAX];
  GtkWidget *ghub_section;
  GtkWidget *gauth_section;
  GtkWidget *apps_section;
  GtkWidget *gpms_button;
  GtkWidget *gctrl_button;
  GtkWidget *agent_button;
  GtkWidget *d1;
  GtkWidget *d2;
  GtkWidget *d3;
  GtkWidget *d4;
  GtkWidget *d5;
  GtkWidget *d6;
  GtkWidget *d7;
  GtkWidget *d8;
  GtkWidget *ghub_cc;
  GtkWidget *ghub_gauth;
  GtkWidget *ghub_gctrl;
  GtkWidget *ghub_agent;
  GtkWidget *ghub_apps;
  GtkWidget *agent_gpms;
  GtkWidget *apps_view;
  GtkWidget *apps_list;
  GtkWidget *log_label;
  GtkWidget *log_section;
  GtkWidget *gctrl_menu;
  GtkWidget *agent_menu;
  GtkWidget *cc_image;
  GtkWidget *ghub_image;
  GtkWidget *gauth_image;
  GtkWidget *gctrl_image;
  GtkWidget *agent_image;
  GtkWidget *gpms_image;
  GtkWidget *full_log_label;
  GtkWidget *log_window;
  GtkWidget *log_button;
  GtkWidget *security_framework_notebook;
  GtkWidget *no_security_framework_label;
  gboolean   animating;
  gboolean   policy_reload_flag;
  gint       policy_reload_seq;
  gint       cur_seq;
  gint       apps_num;
  gint       init_num;
  guint      event_source_tag[SOURCE_FUNC_NUM];
  gchar     *log_message[LOG_BUF];
  gchar     *full_log;
  gchar     *from_log;
  gchar     *tailing_file;
  FILE      *fp;
  long       fpos;
  gint       event_cnt;
  gint       scene;
  gint       scene_cnt;
  gint       log_start;
  gint       log_end;
  gint       log_cnt;
  gint       from;
  gint       to;
  gint       topology;
};

G_DEFINE_TYPE (CcSecurityFrameworkPanel, cc_security_framework_panel, CC_TYPE_PANEL)


security_app *apps[APPS_MAX];
int           selected_app;

static void     do_drawing (GtkWidget *, cairo_t *, gint, gint, gint, gint);
static gboolean scene_presenter (CcSecurityFrameworkPanel *self);
static gboolean modules_state_updater (CcSecurityFrameworkPanel *self);

static security_app *
find_app (CcSecurityFrameworkPanel *self, const char *dbus_name)
{
  int i;

  for (i = 0; i < self->apps_num; i++)
  {
    if (!strcmp (dbus_name, apps[i]->dbus_name))
      return apps[i];
  }
  return NULL;
}

static void
enqueue_log_label (CcSecurityFrameworkPanel *self, char *new_log_message)
{
  if (new_log_message == NULL)
    return;

  self->full_log = g_strjoin ("\t", self->full_log, new_log_message, "\n", NULL);
  self->log_end = (self->log_end+1)%LOG_BUF;

  if (self->log_cnt == LOG_BUF)
  {
    g_free (self->log_message[self->log_start]);
    self->log_start = (self->log_start+1)%LOG_BUF;
  }
  else
    self->log_cnt++;

  self->log_message[self->log_end] = g_strdup (new_log_message);
}

static void
set_line_color (cairo_t *cr,
                gint     color)
{
  switch (color)
  {
    case COLOR_BLACK:
      cairo_set_source_rgba (cr, 0.7, 0.7, 0.7, 1);
      break;
    case COLOR_RED:
      cairo_set_source_rgba (cr, 0.71, 0.06, 0.15, 1);
      break;
    case COLOR_GREEN:
      cairo_set_source_rgba (cr, 0.44, 0.74, 0.12, 1);
      break;
    case COLOR_BLUE:
      cairo_set_source_rgba (cr, 0.05, 0.39, 0.82, 1);
      break;
    case COLOR_YELLOW:
      cairo_set_source_rgba (cr, 0.9, 0.9, 0.1, 1);
      break;
    default:
      cairo_set_source_rgba (cr, 0.64, 0.64, 0.64, 1);
      break;
  }
}

static void
draw_vertical_bar (GtkWidget *widget,
                   cairo_t   *cr,
                   gpointer   user_data)
{
  double dashed[] = { 3.0 };

  set_line_color (cr, COLOR_BLACK);
  cairo_set_line_width (cr, 2.0);
  cairo_set_dash (cr, dashed, 1, 0);

  cairo_move_to (cr, 48, 0);
  cairo_line_to (cr, 48, 73);
  cairo_stroke (cr);
}

static void
draw_conn_ghub_cc (GtkWidget *widget,
                   cairo_t   *cr,
                   gpointer   user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;
  security_app *cc = find_app (self, CC_DBUS);
  int color;

  if (cc && cc->auth_stat)
    color = COLOR_GREEN;
  else
    color = COLOR_NONE;

  do_drawing (widget, cr, DIRECTION_GHUB_CC, color, self->scene, self->scene_cnt);
}

static void
draw_conn_ghub_gauth (GtkWidget *widget,
                      cairo_t   *cr,
                      gpointer   user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;
  security_app *ghub = find_app (self, GHUB_DBUS);
  int color;

  if (ghub && ghub->auth_stat)
    color = COLOR_GREEN;
  else
    color = COLOR_NONE;

  do_drawing (widget, cr, DIRECTION_GHUB_GAUTH, color, self->scene, self->scene_cnt);
}

static void
draw_conn_ghub_gctrl (GtkWidget *widget,
                      cairo_t   *cr,
                      gpointer   user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;
  security_app *gctrl = find_app (self, GCTRL_DBUS);
  int color;

  if (gctrl && gctrl->auth_stat)
    color = COLOR_GREEN;
  else
    color = COLOR_NONE;

  do_drawing (widget, cr, DIRECTION_GHUB_GCTRL, color, self->scene, self->scene_cnt);
}

static void
draw_conn_ghub_agent (GtkWidget *widget,
                       cairo_t   *cr,
                       gpointer   user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;
  security_app *agent = find_app (self, AGENT_DBUS);
  int color;

  if (agent && agent->auth_stat)
    color = COLOR_GREEN;
  else
    color = COLOR_NONE;

  do_drawing (widget, cr, DIRECTION_GHUB_AGENT, color, self->scene, self->scene_cnt);
}

static void
draw_conn_ghub_apps (GtkWidget *widget,
                     cairo_t   *cr,
                     gpointer   user_data)
{
  int color = COLOR_NONE;
  int i;
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;

  for (i = 0; i < self->apps_num; i++)
  {
    if (apps[i]->cell_ref == APPS
        && apps[i]->auth_stat)
    {
      color = COLOR_GREEN;
      break;
    }
  }
  do_drawing (widget, cr, DIRECTION_GHUB_APPS, color, self->scene, self->scene_cnt);
}

static void
draw_conn_agent_gpms (GtkWidget *widget,
                       cairo_t   *cr,
                       gpointer   user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;
  security_app *agent = find_app (self, AGENT_DBUS);
  int color;

  if (agent && agent->exe_stat)
    color = COLOR_BLUE;
  else
    color = COLOR_NONE;

  do_drawing (widget, cr, DIRECTION_AGENT_GPMS, color, self->scene, self->scene_cnt);
}

static void
log_button_clicked (GtkWidget *widget,
                    gpointer   user_data)
{
  GtkWidget *log_window;
  GtkWidget *scrolled_window;
  GtkWidget *full_log_label;
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;

  log_window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  scrolled_window = gtk_scrolled_window_new (NULL, NULL);
  full_log_label = gtk_label_new ("");
  gtk_label_set_xalign (GTK_LABEL (full_log_label), 0);
  gtk_label_set_yalign (GTK_LABEL (full_log_label), 0);
  gtk_label_set_text (GTK_LABEL (full_log_label), self->full_log);
  gtk_container_add (GTK_CONTAINER (scrolled_window), full_log_label);
  gtk_container_add (GTK_CONTAINER (log_window), scrolled_window);
  gtk_window_set_title (GTK_WINDOW (log_window), _("Panel Log"));
  gtk_window_set_default_size (GTK_WINDOW (log_window), 400, 400);
  gtk_window_set_position (GTK_WINDOW (log_window), GTK_WIN_POS_MOUSE);

  gtk_widget_show_all (log_window);
}

static void
gpms_cell_clicked (GtkWidget      *widget,
                   GdkEventButton *event,
                   gpointer        user_data)
{
  pid_t pid;
  GKeyFile *key_file;
  char *gpms_uri = NULL;
  GtkWidget *dialog = NULL;
  GtkWidget *content = NULL;

  key_file = g_key_file_new ();
  if (g_key_file_load_from_file (key_file, GCSR_CONF, G_KEY_FILE_NONE, NULL))
  {
    gpms_uri = g_strconcat ("https://", g_key_file_get_string (key_file, "domain", "gpms", NULL), NULL);
    if (event->button == GDK_BUTTON_PRIMARY)
    {
      pid = fork ();
      if (pid == 0)
      {
        execl ("/usr/bin/gooroom-browser", "gooroom-browser", gpms_uri, NULL);
        exit (EXIT_SUCCESS);
      }
    }
    if (gpms_uri)
      g_free (gpms_uri);
  }
  else
  {
    dialog = gtk_dialog_new_with_buttons (_("Control Center"),
                                          NULL,
                                          GTK_DIALOG_MODAL,
                                          _("OK"),
                                          GTK_RESPONSE_ACCEPT,
                                          NULL);
    content = gtk_dialog_get_content_area (GTK_DIALOG (dialog));
    gtk_container_add (GTK_CONTAINER (content), gtk_label_new (_("\n\nDevice Not Registered.\n\n")));
    gtk_window_set_default_size (GTK_WINDOW (dialog),
                                 200, 100);
    gtk_window_set_position (GTK_WINDOW (dialog), GTK_WIN_POS_CENTER);
    gtk_widget_show_all (content);
    gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);
  }
  g_key_file_free (key_file);
}

static void
gctrl_cell_clicked (GtkWidget      *widget,
                    GdkEventButton *event,
                    gpointer        user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;

  if (event->button == GDK_BUTTON_SECONDARY)
    gtk_menu_popup_at_pointer (GTK_MENU (self->gctrl_menu), NULL);
}

static void
agent_cell_clicked (GtkWidget      *widget,
                    GdkEventButton *event,
                    gpointer        user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel *) user_data;

  if (event->button == GDK_BUTTON_SECONDARY)
    gtk_menu_popup_at_pointer (GTK_MENU (self->agent_menu), NULL);
}

static void
app_cell_clicked (GtkWidget      *widget,
                  GdkEventButton *event,
                  gpointer        user_data)
{
  if (event->button == GDK_BUTTON_PRIMARY)
  {
  }
  else if (event->button == GDK_BUTTON_SECONDARY)
    gtk_menu_popup_at_pointer (GTK_MENU (apps[GPOINTER_TO_INT (user_data)]->app_menu), NULL);
}

static void
v3_cell_clicked (GtkWidget      *widget,
                 GdkEventButton *event,
                 gpointer        user_data)
{
  pid_t pid;
  char *v3_domain = "http://localhost:88";
  char *argv[] = { "gooroom-browser", v3_domain, NULL };

  if (event->button == GDK_BUTTON_PRIMARY)
  {
    pid = fork ();
    if (pid == 0)
    {
      execv ("/usr/bin/gooroom-browser", argv);
      exit (EXIT_SUCCESS);
    }
  }
  else if (event->button == GDK_BUTTON_SECONDARY)
    gtk_menu_popup_at_pointer (GTK_MENU (apps[GPOINTER_TO_INT (user_data)]->app_menu), NULL);
}

static gchar *
dbus_message_sender (gpointer arg_p)
{
  int arg = GPOINTER_TO_INT (arg_p);
  lsf_user_data_t app_data;
  int ret;
  int r;
  char *func = NULL;
  char param[PARAM_BUF];
  char *response = NULL;
  char *req_msg = malloc (DEFAULT_BUF_SIZE);

  memset (req_msg, 0, DEFAULT_BUF_SIZE);

  switch (arg)
  {
    case GET_CONFIG:
      func = "getsettings";
      snprintf (param, PARAM_BUF, "");
      break;
    case SET_CONFIG:
      func = "setsettings";
      snprintf (param,
                PARAM_BUF,
                "\"policy\":[{\
                 \"dbus_name\": \"%s\",\
                 \"abs_path\": \"/usr/bin/gcontroller\",\
                 \"settings\": {\
                 \"topology_on\": \"true\"}}]",
                 GCTRL_DBUS);
      break;
    case UNSET_CONFIG:
      func = "setsettings";
      snprintf (param,
                PARAM_BUF,
                "\"policy\":[{\
                 \"dbus_name\": \"%s\",\
                 \"abs_path\": \"/usr/bin/gcontroller\",\
                 \"settings\": {\
                 \"topology_on\": \"false\"}}]",
                 GCTRL_DBUS);
      break;
    case LAUNCH_AGENT:
      func = "start";
      snprintf (param,
                PARAM_BUF,
                "\"targets\": \"%s\"",
                AGENT_DBUS);
      break;
    case KILL_AGENT:
      func = "stop";
      snprintf (param,
                PARAM_BUF,
                "\"targets\": \"%s\"",
                AGENT_DBUS);
      break;
    case LAUNCH_APP:
      func = "start";
      snprintf (param,
                PARAM_BUF,
                "\"targets\": \"%s\"",
                apps[selected_app]->dbus_name);
      break;
    case KILL_APP:
      func = "stop";
      snprintf (param,
                PARAM_BUF,
                "\"targets\": \"%s\"",
                apps[selected_app]->dbus_name);
      break;
    case GET_STATUS:
      func = "app_status";
      snprintf (param,
                PARAM_BUF,
                "\"targets\": \"all\"");
      break;
  }
  snprintf (req_msg,
            DEFAULT_BUF_SIZE,
            "{  \"to\": \"%s\",\
                \"from\": \"%s\",\
                \"access_token\": \"%s\",\
                \"function\": \"%s\",\
                \"params\": {%s}}",
            GCTRL_DBUS,
            CC_DBUS,
            lsf_panel_access_token,
            func,
            param);
  ret = lsf_send_message (lsf_panel_symm_key, req_msg, &response);
  free (req_msg);
  if (ret == LSF_MESSAGE_SEND_ERROR)
  {
    g_print ("LSF_MESSAGE_SEND_ERROR\n");
    free (response);
    response = NULL;
  }
  if (ret == LSF_MESSAGE_RE_AUTH)
  {
    g_print ("LSF_MESSAGE_RE_AUTH\n");
    r = lsf_auth (&app_data, CC_PASSPHRASE);
    if (r == LSF_AUTH_STAT_OK)
    {
      lsf_panel_symm_key = g_strdup (app_data.symm_key);
      lsf_panel_access_token = g_strdup (app_data.access_token);
      dbus_message_sender (GINT_TO_POINTER (GET_CONFIG));
    }
    free (response);
    response = NULL;
  }
  return response;
}

static void
gctrl_menu_handler (GtkWidget *widget,
                    GdkEvent  *event,
                    gpointer   user_data)
{
  const gchar *selection = gtk_menu_item_get_label (GTK_MENU_ITEM (widget));
  GThread *thr;
  char *ret;

  if (gtk_check_menu_item_get_active (GTK_CHECK_MENU_ITEM (widget)))
  {
    if (!g_strcmp0 (selection, _("On")))
    {
      thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (SET_CONFIG));
      ret = (char *) g_thread_join (thr);
    }
    else if (!g_strcmp0 (selection, _("Off")))
    {
      thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (UNSET_CONFIG));
      ret = (char *) g_thread_join (thr);
    }
  }
}

static gboolean
app_menu_handler (GtkWidget *widget,
                  gpointer   user_data)
{
  const gchar *selection = gtk_menu_item_get_label (GTK_MENU_ITEM (widget));
  GThread *thr;
  char *ret;

  if (!g_strcmp0 (selection, _("Kill")))
  {
    selected_app = GPOINTER_TO_INT (user_data);
    thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (KILL_APP));
    ret = (char *) g_thread_join (thr);
  }
  else if (!g_strcmp0 (selection, _("Launch")))
  {
    selected_app = GPOINTER_TO_INT (user_data);
    thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (LAUNCH_APP));
    ret = (char *) g_thread_join (thr);
  }

  return FALSE;
}

static void
module_state_update (GtkWidget *widget,
                     gpointer   user_data)
{
  CcSecurityFrameworkPanel *self = (CcSecurityFrameworkPanel*) user_data;
  modules_state_updater (self);
}

static gboolean
agent_menu_handler (GtkWidget *widget,
                     GdkEvent  *event,
                     gpointer   user_data)
{
  const gchar *selection = gtk_menu_item_get_label (GTK_MENU_ITEM (widget));
  GThread   *thr;
  char *ret;

  if (!g_strcmp0 (selection, _("Kill")))
  {
    thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (KILL_AGENT));
    ret = (char *) g_thread_join (thr);
  }
  else if (!g_strcmp0 (selection, _("Launch")))
  {
    thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (LAUNCH_AGENT));
    ret = (char *) g_thread_join (thr);
  }

  return FALSE;
}

static void
set_menu_items (CcSecurityFrameworkPanel *self,
                gint                      module)
{
  GtkWidget *menu;
  GtkWidget *sub_menu;
  GtkWidget *menu_item;
  GtkRadioMenuItem *last_item = NULL;
  GSList *conf_group = NULL;

  if (module == GCTRL)
  {
    menu = self->gctrl_menu;
    menu_item = gtk_menu_item_new_with_label (_("Configuration Management"));
    gtk_menu_attach (GTK_MENU (menu), menu_item, 0, 1, 0, 1);
    sub_menu = gtk_menu_new ();
    gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_item), sub_menu);
    menu_item = gtk_radio_menu_item_new_with_label (conf_group, _("On"));
    if (self->topology)
      gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (menu_item), TRUE);
    g_signal_connect (G_OBJECT (menu_item),
                      "toggled",
                      G_CALLBACK (gctrl_menu_handler),
                      self);
    gtk_menu_attach (GTK_MENU (sub_menu), menu_item, 0, 1, 0, 1);
    conf_group = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (menu_item));
    gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (menu_item), TRUE);
    menu_item = gtk_radio_menu_item_new_with_label (conf_group, _("Off"));
    if (!self->topology)
      gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (menu_item), TRUE);
    g_signal_connect (G_OBJECT (menu_item),
                      "toggled",
                      G_CALLBACK (gctrl_menu_handler),
                      self);
    gtk_menu_attach (GTK_MENU (sub_menu), menu_item, 0, 1, 1, 2);
    gtk_widget_show_all (menu);
  }
  else if (module == AGENT)
  {
    menu = self->agent_menu;
    menu_item = gtk_menu_item_new_with_label (_("Launch"));
    gtk_menu_attach (GTK_MENU (menu), menu_item, 0, 1, 0, 1);
    g_signal_connect (G_OBJECT (menu_item),
                      "activate",
                      G_CALLBACK (agent_menu_handler),
                      NULL);
    g_signal_connect_after (G_OBJECT (menu_item),
                            "activate",
                            G_CALLBACK (module_state_update),
                            self);
    menu_item = gtk_menu_item_new_with_label (_("Kill"));
    gtk_menu_attach (GTK_MENU (menu), menu_item, 0, 1, 1, 2);
    g_signal_connect (G_OBJECT (menu_item),
                      "activate",
                      G_CALLBACK (agent_menu_handler),
                      NULL);
    g_signal_connect_after (G_OBJECT (menu_item),
                            "activate",
                            G_CALLBACK (module_state_update),
                            self);
    gtk_widget_show_all (menu);
  }
}

static void
set_modules_opacity (CcSecurityFrameworkPanel *self)
{
  int i;
  security_app *app = NULL;

  if (self->apps_num > 0)
  {
    gtk_widget_set_opacity (self->apps_section, 1.0);
    for (i = 0; i < self->apps_num; i++)
    {
      switch (apps[i]->cell_ref)
      {
        case CC:
          break;
        case GHUB:
          if (apps[i]->exe_stat)
            gtk_widget_set_opacity (self->ghub_section, 1.0);
          else
            gtk_widget_set_opacity (self->ghub_section, 0.3);
          break;
        case GAUTH:
          if (apps[i]->exe_stat)
            gtk_widget_set_opacity (self->gauth_section, 1.0);
          else
            gtk_widget_set_opacity (self->gauth_section, 0.3);
          break;
        case GCTRL:
          if (apps[i]->exe_stat)
            gtk_widget_set_opacity (self->gctrl_button, 1.0);
          else
            gtk_widget_set_opacity (self->gctrl_button, 0.3);
          break;
        case AGENT:
          if (apps[i]->exe_stat)
            gtk_widget_set_opacity (self->agent_button, 1.0);
          else
            gtk_widget_set_opacity (self->agent_button, 0.3);
          break;
        case APPS:
          if (apps[i]->exe_stat)
            gtk_widget_set_opacity (apps[i]->app_button, 1.0);
          else
            gtk_widget_set_opacity (apps[i]->app_button, 0.3);
          break;
      }
    }
  }
  else
  {
    gtk_widget_set_opacity (self->ghub_section, 0.3);
    gtk_widget_set_opacity (self->gauth_section, 0.3);
    gtk_widget_set_opacity (self->gctrl_button, 0.3);
    gtk_widget_set_opacity (self->agent_button, 0.3);
    gtk_widget_set_opacity (self->apps_section, 0.3);
  }
}

static void
draw_lines (CcSecurityFrameworkPanel *self)
{
  gtk_widget_queue_draw (self->d1);
  gtk_widget_queue_draw (self->d2);
  gtk_widget_queue_draw (self->d3);
  gtk_widget_queue_draw (self->d4);
  gtk_widget_queue_draw (self->d5);
  gtk_widget_queue_draw (self->d6);
  gtk_widget_queue_draw (self->d7);
  gtk_widget_queue_draw (self->d8);
}

static void
do_drawing (GtkWidget *widget,
            cairo_t   *cr,
            gint       direction,
            gint       color,
            gint       scene,
            gint       scene_cnt)
{
  int i;
  int reverse = NORM;
  gboolean color_scope = FALSE;
  gboolean vert_bar = FALSE;
  int right_xpos = 78;
  int mid_xpos = 46;
  int left_xpos = 18;
  int up_ypos = 12;
  int mid_ypos = 35;
  int down_ypos = 60;
  double dashed[] = { 3.0 };
  int ht = HT;
  int vt = VT;
  int xpos;
  int ypos;

  cairo_set_line_width (cr, 2.0);
  set_line_color (cr, color);

  switch (scene)
  {
    case SCENE_METHOD_CALL:
      if (STARTING_BLINK_CNT < scene_cnt
          && scene_cnt < STARTING_BLINK_CNT+MOVING_CNT)
        color_scope = TRUE;
      break;
    case SCENE_METHOD_CALL_REV:
      if (STARTING_BLINK_CNT < scene_cnt
          && scene_cnt < STARTING_BLINK_CNT+MOVING_CNT)
      {
        color_scope = TRUE;
        reverse = REV;
      }
      break;
  }

  switch (direction)
  {
    case DIRECTION_GHUB_GAUTH:
      xpos = mid_xpos;
      ypos = down_ypos;
      ht = 0;
      vt *= -1;
      break;
    case DIRECTION_GHUB_GCTRL:
      xpos = left_xpos;
      ypos = down_ypos;
      ht *= 1;
      vt *= -1;
      break;
    case DIRECTION_GHUB_AGENT:
      switch (scene)
      {
        case SCENE_POLICY_RELOAD:
          if (ENDING_BLINK_CNT < scene_cnt
              && scene_cnt < ENDING_BLINK_CNT+MOVING_CNT)
          {
            color_scope = TRUE;
            reverse = REV;
          }
          break;
      }
      xpos = left_xpos;
      ypos = mid_ypos;
      vt = 0;
      break;
    case DIRECTION_AGENT_GPMS:
      switch (scene)
      {
        case SCENE_POLICY_RELOAD:
          if (STARTING_BLINK_CNT < scene_cnt
              && scene_cnt < STARTING_BLINK_CNT+MOVING_CNT)
            color_scope = TRUE;
          break;
      }
      xpos = left_xpos;
      ypos = mid_ypos;
      vt = 0;
      vert_bar = TRUE;
      break;
    case DIRECTION_GHUB_APPS:
      xpos = mid_xpos;
      ypos = up_ypos;
      ht = 0;
      vt *= 1;
      break;
    case DIRECTION_GHUB_CC:
      xpos = left_xpos;
      ypos = mid_ypos;
      vt = 0;
      vert_bar = TRUE;
      break;
  }

  for (i = 0; i < 4; i++)
  {
    if (color_scope)
    {
      if (((scene_cnt+i+reverse)%2))
      {
        set_line_color (cr, color);
        cairo_arc (cr, xpos+(ht*i), ypos+(vt*i), RADIUS_SMALL, 0, 2*M_PI);
      }
      else
      {
        set_line_color (cr, COLOR_YELLOW);
        cairo_arc (cr, xpos+(ht*i), ypos+(vt*i), RADIUS_LARGE, 0, 2*M_PI);
      }
    }
    else
    {
      set_line_color (cr, color);
      cairo_arc (cr, xpos+(ht*i), ypos+(vt*i), RADIUS_MEDIUM, 0, 2*M_PI);
    }
    cairo_fill (cr);
  }

  if (vert_bar)
  {
    set_line_color (cr, COLOR_BLACK);
    cairo_set_dash (cr, dashed, 1, 0);
    cairo_move_to (cr, 48, 0);
    cairo_line_to (cr, 48, 73);
    cairo_stroke (cr);
  }
}

static void
scene_handler (CcSecurityFrameworkPanel *self)
{
  if (self->scene == SCENE_IDLE)
  {
    self->animating = FALSE;
    self->scene_cnt = 0;
    draw_lines (self);
  }
  else
  {
    switch (self->scene_cnt)
    {
      case 0:
        self->animating = TRUE;
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            self->policy_reload_flag = TRUE;
            break;
          case SCENE_METHOD_CALL:
          case SCENE_METHOD_CALL_REV:
            if (self->policy_reload_flag
                && self->policy_reload_seq != self->cur_seq)
              self->policy_reload_flag = FALSE;
            break;
        }
        enqueue_log_label (self, self->from_log);
        break;
      case 1: case 3: case 5:
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            gtk_widget_set_opacity (self->gpms_image, 1.0);
            break;
          case SCENE_METHOD_CALL:
          case SCENE_METHOD_CALL_REV:
            switch (self->from)
            {
              case CC:
                gtk_widget_set_opacity (self->cc_image, 1.0);
                break;
              case GHUB:
                gtk_widget_set_opacity (self->ghub_image, 1.0);
                break;
              case GAUTH:
                gtk_widget_set_opacity (self->gauth_image, 1.0);
                break;
              case GCTRL:
                gtk_widget_set_opacity (self->gctrl_image, 1.0);
                break;
              case AGENT:
                gtk_widget_set_opacity (self->agent_image, 1.0);
                break;
              case GPMS:
                gtk_widget_set_opacity (self->gpms_image, 1.0);
                break;
              case APPS:
                gtk_widget_set_opacity (apps[selected_app]->app_button, 1.0);
                break;
            }
            break;
        }
        break;
      case 2: case 4:
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            gtk_widget_set_opacity (self->gpms_image, 0.3);
            break;
          case SCENE_METHOD_CALL:
          case SCENE_METHOD_CALL_REV:
            switch (self->from)
            {
              case CC:
                gtk_widget_set_opacity (self->cc_image, 0.3);
                break;
              case GHUB:
                gtk_widget_set_opacity (self->ghub_image, 0.3);
                break;
              case GAUTH:
                gtk_widget_set_opacity (self->gauth_image, 0.3);
                break;
              case GCTRL:
                gtk_widget_set_opacity (self->gctrl_image, 0.3);
                break;
              case AGENT:
                gtk_widget_set_opacity (self->agent_image, 0.3);
                break;
              case GPMS:
                gtk_widget_set_opacity (self->gpms_image, 0.3);
                break;
              case APPS:
                gtk_widget_set_opacity (apps[selected_app]->app_button, 0.3);
                break;
            }
            break;
        }
        draw_lines (self);
        break;
      case 6: case 7: case 8: case 9: case 10:
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            gtk_widget_queue_draw (self->agent_gpms);
            break;
          case SCENE_METHOD_CALL:
            switch (self->from)
            {
              case CC:
                gtk_widget_queue_draw (self->ghub_cc);
                break;
              case GAUTH:
                gtk_widget_queue_draw (self->ghub_gauth);
                break;
              case GCTRL:
                gtk_widget_queue_draw (self->ghub_gctrl);
                break;
              case AGENT:
                gtk_widget_queue_draw (self->ghub_agent);
                break;
              case APPS:
                gtk_widget_queue_draw (self->ghub_apps);
                break;
              case GPMS:
                gtk_widget_queue_draw (self->agent_gpms);
                break;
            }
            break;
          case SCENE_METHOD_CALL_REV:
            switch (self->to)
            {
              case CC:
                gtk_widget_queue_draw (self->ghub_cc);
                break;
              case GAUTH:
                gtk_widget_queue_draw (self->ghub_gauth);
                break;
              case GCTRL:
                gtk_widget_queue_draw (self->ghub_gctrl);
                break;
              case AGENT:
                gtk_widget_queue_draw (self->ghub_agent);
                break;
              case APPS:
                gtk_widget_queue_draw (self->ghub_apps);
                break;
              case GPMS:
                gtk_widget_queue_draw (self->agent_gpms);
                break;
            }
            break;
        }
        break;
      case 11: case 13: case 15:
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            gtk_widget_set_opacity (self->agent_image, 1.0);
            break;
          case SCENE_METHOD_CALL:
          case SCENE_METHOD_CALL_REV:
            switch (self->to)
            {
              case CC:
                gtk_widget_set_opacity (self->cc_image, 1.0);
                break;
              case GHUB:
                gtk_widget_set_opacity (self->ghub_image, 1.0);
                break;
              case GAUTH:
                gtk_widget_set_opacity (self->gauth_image, 1.0);
                break;
              case GCTRL:
                gtk_widget_set_opacity (self->gctrl_image, 1.0);
                break;
              case AGENT:
                gtk_widget_set_opacity (self->agent_image, 1.0);
                break;
              case GPMS:
                gtk_widget_set_opacity (self->gpms_image, 1.0);
                break;
              case APPS:
                if (self->scene_cnt == 15 && !apps[selected_app]->exe_stat)
                  gtk_widget_set_opacity (apps[selected_app]->app_button, 0.3);
                else
                  gtk_widget_set_opacity (apps[selected_app]->app_button, 1.0);
                break;
            }
            break;
        }
        break;
      case 12: case 14:
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            gtk_widget_set_opacity (self->agent_image, 0.3);
            break;
          case SCENE_METHOD_CALL:
          case SCENE_METHOD_CALL_REV:
            switch (self->to)
            {
              case CC:
                gtk_widget_set_opacity (self->cc_image, 0.3);
                break;
              case GHUB:
                gtk_widget_set_opacity (self->ghub_image, 0.3);
                break;
              case GAUTH:
                gtk_widget_set_opacity (self->gauth_image, 0.3);
                break;
              case GCTRL:
                gtk_widget_set_opacity (self->gctrl_image, 0.3);
                break;
              case AGENT:
                gtk_widget_set_opacity (self->agent_image, 0.3);
                break;
              case GPMS:
                gtk_widget_set_opacity (self->gpms_image, 0.3);
                break;
              case APPS:
                gtk_widget_set_opacity (apps[selected_app]->app_button, 0.3);
                break;
            }
            break;
        }
        break;
      case 16:
        switch (self->scene)
        {
          case SCENE_POLICY_RELOAD:
            self->scene = SCENE_METHOD_CALL;
            self->from = AGENT;
            self->to = GHUB;
            break;
          default:
            self->scene = SCENE_IDLE;
            self->animating = FALSE;
            break;
        }
        self->scene_cnt = SCENE_END;
        draw_lines (self);
        break;
    }
    self->scene_cnt = (self->scene_cnt+1)%SCENE_CNT;
  }
}

static int
get_cell_ref (const char *dbus_name)
{
  int i;

  for (i = CC; i < GPMS; i++)
  {
    if (!g_strcmp0 (dbus_name, lsf_dbus_name[i]))
      return i;
  }

  return APPS;
}

static void
get_scene (CcSecurityFrameworkPanel *self)
{
  gchar **log_str;
  gchar **args;
  security_app *app;
  char *from;
  char *to;
  char buf[DEFAULT_BUF_SIZE];

  if (self->scene == SCENE_IDLE)
  {
    if (self->fp == NULL)
    {
      self->fp = fopen (self->tailing_file, "r");
      if (self->fp != NULL)
      {
        fseek (self->fp, 0, SEEK_END);
        self->fpos = ftell (self->fp);
      }
      else
        return;
    }
    else
      fseek (self->fp, self->fpos, SEEK_SET);

    if (fgets (buf, DEFAULT_BUF_SIZE, self->fp) == NULL)
    {
      self->scene = SCENE_IDLE;
      return;
    }

    log_str = g_strsplit (buf, " ", 0);
    args = g_strsplit (log_str[2], ",", 0);
    self->cur_seq = atoi (args[DMSG_SEQ]);
    self->from = get_cell_ref (args[DMSG_FROM]);
    self->to = get_cell_ref (args[DMSG_TO]);

    if (self->from == -1 || self->to == -1)
    {
      self->fpos = ftell (self->fp);
      g_strfreev (args);
      g_strfreev (log_str);
      return;
    }

    if (self->from == APPS)
    {
      app = find_app (self, args[DMSG_FROM]);
      if (app)
      {
        from = app->display_name;
        selected_app = app->app_idx;
      }
      else
        from = args[DMSG_FROM];
    }
    else
      from = module_name[self->from];

    if (self->to == APPS)
    {
      app = find_app (self, args[DMSG_TO]);
      if (app)
      {
        to = app->display_name;
        selected_app = app->app_idx;
      }
      else
        from = args[DMSG_TO];
    }
    else
      to = module_name[self->to];

    self->from_log = g_strconcat (from, "\t-->\t", to, "\t", args[DMSG_GLYPH], " , ", args[DMSG_FUNC], NULL);

    if (!g_strcmp0 (args[DMSG_GLYPH], "O") &&
        self->from == AGENT &&
        self->to == GHUB)
    {
      self->policy_reload_seq = atoi (args[DMSG_SEQ]);
      self->scene = SCENE_POLICY_RELOAD;
    }
    else
    {
      if (self->from == GHUB)
        self->scene = SCENE_METHOD_CALL_REV;
      else
        self->scene = SCENE_METHOD_CALL;
    }

    if (args)
      g_strfreev (args);

    if (log_str)
      g_strfreev (log_str);

    self->fpos = ftell (self->fp);
  }
}

static gboolean
scene_presenter (CcSecurityFrameworkPanel *self)
{
  if (!self->animating)
    get_scene (self);
  scene_handler (self);

  return TRUE;
}

static int
get_topology (char *resp)
{
  struct json_object *resp_obj = NULL;
  struct json_object *module_obj = NULL;
  struct json_object *field_iter = NULL;
  int i;
  int module_len;
  int ret = TRUE;

  resp_obj = json_tokener_parse (resp);

  if (!resp_obj) goto GET_TOPOLOGY_ERROR;
  if (!json_object_object_get_ex (resp_obj, "return", &resp_obj)) goto GET_TOPOLOGY_ERROR;
  if (!json_object_object_get_ex (resp_obj, "value", &resp_obj)) goto GET_TOPOLOGY_ERROR;
  module_len = json_object_array_length (resp_obj);
  if (module_len <= 0) goto GET_TOPOLOGY_ERROR;
  for (i = 0; i < module_len; i++)
  {
    module_obj = json_object_array_get_idx (resp_obj, i);
    if (!module_obj) goto GET_TOPOLOGY_ERROR;
    if (!json_object_object_get_ex (module_obj, "dbus_name", &field_iter)) goto GET_TOPOLOGY_ERROR;
    if (g_strcmp0 (GCTRL_DBUS, json_object_get_string (field_iter))) continue;
    else {
      if (!json_object_object_get_ex (module_obj, "settings", &field_iter)) goto GET_TOPOLOGY_ERROR;
      if (!json_object_object_get_ex (field_iter, "topology_on", &field_iter)) goto GET_TOPOLOGY_ERROR;
      if (!g_strcmp0 ("false", json_object_get_string (field_iter)))
          ret = FALSE;
      break;
    }
  }

GET_TOPOLOGY_ERROR:
  if (resp_obj) json_object_put (resp_obj);
  if (field_iter) json_object_put (field_iter);
  if (module_obj) json_object_put (module_obj);

  return ret;
}

static int
resp_parser (char *resp)
{
  security_app *app = NULL;
  struct json_object *resp_obj = NULL;
  struct json_object *module_obj = NULL;
  struct json_object *field_iter = NULL;
  struct json_object *stat_iter = NULL;
  int i, j;
  int module_len;

  resp_obj = json_tokener_parse (resp);

  if (!resp_obj) goto RESP_PARSER_ERROR;
  if (!json_object_object_get_ex (resp_obj, "return", &resp_obj)) goto RESP_PARSER_ERROR;
  if (!json_object_object_get_ex (resp_obj, "result", &resp_obj)) goto RESP_PARSER_ERROR;
  module_len = json_object_array_length (resp_obj);
  if (module_len <= 0) goto RESP_PARSER_ERROR;
  for (i = 0; i < module_len; i++)
  {
    module_obj = json_object_array_get_idx (resp_obj, i);
    if (!module_obj) goto RESP_PARSER_ERROR;

    if (apps[i])
    {
      free (apps[i]);
      apps[i] = NULL;
    }
    apps[i] = (security_app *) calloc (1, sizeof (security_app));
    apps[i]->set = FALSE;
    apps[i]->app_idx = i;

    if (!json_object_object_get_ex (module_obj, "dbus_name", &field_iter)) goto RESP_PARSER_ERROR;
    apps[i]->dbus_name = g_strdup (json_object_get_string (field_iter));
    apps[i]->cell_ref = get_cell_ref (apps[i]->dbus_name);

    if (!json_object_object_get_ex (module_obj, "display_name", &field_iter)) goto RESP_PARSER_ERROR;
    apps[i]->display_name = g_strdup (json_object_get_string (field_iter));

    if (!json_object_object_get_ex (module_obj, "status", &field_iter)) goto RESP_PARSER_ERROR;
    field_iter = json_object_array_get_idx (field_iter, 0);

    if (!field_iter) goto RESP_PARSER_ERROR;
    if (!json_object_object_get_ex (field_iter, "exe_stat", &stat_iter)) goto RESP_PARSER_ERROR;
    if (!g_strcmp0 (json_object_get_string (stat_iter), "running"))
    {
      apps[i]->exe_stat = TRUE;
      if (!json_object_object_get_ex (field_iter, "auth_stat", &stat_iter)) goto RESP_PARSER_ERROR;
      if (!g_strcmp0 (json_object_get_string (stat_iter), "auth"))
        apps[i]->auth_stat = TRUE;
      else
        apps[i]->auth_stat = FALSE;
    }
    else
    {
      apps[i]->exe_stat = FALSE;
      apps[i]->auth_stat = FALSE;
    }

  }
  json_object_put (resp_obj);

  return module_len;

RESP_PARSER_ERROR:
  if (resp_obj) json_object_put (resp_obj);
  if (field_iter) json_object_put (field_iter);
  if (module_obj) json_object_put (module_obj);

  return -1;
}

static void
set_apps (CcSecurityFrameworkPanel *self)
{
  GtkWidget *menu_item;
  char img_file[BUFSIZ];
  int i, j;

  gtk_widget_destroy (self->apps_list);
  self->apps_list = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 10);
  gtk_container_add (GTK_CONTAINER (self->apps_view), self->apps_list);

  for (i = 0; i < self->apps_num; i++)
  {
    if (APPS == apps[i]->cell_ref)
    {
      apps[i]->app_button = gtk_button_new_with_label (apps[i]->display_name);
      snprintf (img_file,
                BUFSIZ,
                "/var/tmp/lsf/lsf-cc-panel/%s/resources/icon/app.svg",
                apps[i]->dbus_name);
      if (access (img_file, R_OK) == 0)
        gtk_button_set_image (GTK_BUTTON (apps[i]->app_button), gtk_image_new_from_file (img_file));
      else
        gtk_button_set_image (GTK_BUTTON (apps[i]->app_button), gtk_image_new_from_resource (APPS_IMG));

      gtk_button_set_image_position (GTK_BUTTON (apps[i]->app_button), GTK_POS_TOP);
      gtk_button_set_always_show_image (GTK_BUTTON (apps[i]->app_button), TRUE);
      gtk_button_set_relief (GTK_BUTTON (apps[i]->app_button), GTK_RELIEF_NONE);

      if (!g_strcmp0 (apps[i]->dbus_name, "kr.gooroom.ahnlab.v3"))
        g_signal_connect (G_OBJECT (apps[i]->app_button),
                          "button-press-event",
                          G_CALLBACK (v3_cell_clicked),
                          GINT_TO_POINTER (i));
      else
        g_signal_connect (G_OBJECT (apps[i]->app_button),
                          "button-press-event",
                          G_CALLBACK (app_cell_clicked),
                          GINT_TO_POINTER (i));
      gtk_widget_show_all (apps[i]->app_button);

      apps[i]->app_menu = gtk_menu_new ();
      menu_item = gtk_menu_item_new_with_label (_("Launch"));
      gtk_menu_attach (GTK_MENU (apps[i]->app_menu), menu_item, 0, 1, 0, 1);
      g_signal_connect (G_OBJECT (menu_item),
                        "activate",
                        G_CALLBACK (app_menu_handler),
                        GINT_TO_POINTER (i));
      g_signal_connect_after (G_OBJECT (menu_item),
                              "activate",
                              G_CALLBACK (module_state_update),
                              self);
      menu_item = gtk_menu_item_new_with_label (_("Kill"));
      gtk_menu_attach (GTK_MENU (apps[i]->app_menu), menu_item, 0, 1, 1, 2);
      g_signal_connect (G_OBJECT (menu_item),
                        "activate",
                        G_CALLBACK (app_menu_handler),
                        GINT_TO_POINTER (i));
      g_signal_connect_after (G_OBJECT (menu_item),
                              "activate",
                              G_CALLBACK (module_state_update),
                              self);
      gtk_widget_show_all (apps[i]->app_menu);

      gtk_container_add (GTK_CONTAINER (self->apps_list), apps[i]->app_button);
      apps[i]->set = TRUE;
    }
  }
  gtk_widget_show_all (self->apps_list);
}

static gboolean
modules_state_updater (CcSecurityFrameworkPanel *self)
{
  GThread *thr;
  int i, j;
  int target_cell;
  int ret_num;
  char *ret = NULL;
  gboolean err = FALSE;

  thr = g_thread_new (NULL, (gpointer) dbus_message_sender, GINT_TO_POINTER (GET_STATUS));
  ret = (char *) g_thread_join (thr);

  if (!ret)
    err = TRUE;
  else
  {
    ret_num = resp_parser (ret);
    if (ret_num == -1)
      err = TRUE;
    else
    {
      if (self->apps_num != ret_num)
        self->apps_num = ret_num;
    }
  }

  set_apps (self);
  set_modules_opacity (self);

  return TRUE;
}

static const char *
cc_security_framework_panel_get_help_uri (CcPanel *self)
{
  return "help:gnome-help/security-framework";
}

static void
cc_security_framework_panel_dispose (GObject *object)
{
  CcSecurityFrameworkPanel *self = CC_SECURITY_FRAMEWORK_PANEL (object);
  int i;

  if (self->event_cnt)
  {
    for (i = 0; i < self->event_cnt; i++)
      g_source_remove (self->event_source_tag[i]);
    self->event_cnt = 0;
  }

  if (self->fp != NULL)
  {
    fclose (self->fp);
    self->fp = NULL;
  }

  G_OBJECT_CLASS (cc_security_framework_panel_parent_class)->dispose (object);
}

static void
cc_security_framework_panel_constructed (GObject *object)
{
  CcSecurityFrameworkPanel *self = CC_SECURITY_FRAMEWORK_PANEL (object);

  self->event_source_tag[SOURCE_FUNC_PRESENTER] = g_timeout_add (PRESENTER_TIMEOUT, (GSourceFunc) scene_presenter, (gpointer) self);
  self->event_cnt++;
  self->event_source_tag[SOURCE_FUNC_UPDATER] = g_timeout_add (UPDATER_TIMEOUT, (GSourceFunc) modules_state_updater, (gpointer) self);
  self->event_cnt++;
}

static void
cc_security_framework_panel_class_init (CcSecurityFrameworkPanelClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GtkWidgetClass *widget_class = GTK_WIDGET_CLASS (klass);

  object_class->dispose = cc_security_framework_panel_dispose;
  object_class->constructed = cc_security_framework_panel_constructed;

  gtk_widget_class_set_template_from_resource (widget_class, "/org/gnome/control-center/security-framework/security-framework.ui");
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_section);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, gauth_section);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, apps_section);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, gpms_button);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, gctrl_button);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, agent_button);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_cc);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_gauth);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_gctrl);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_agent);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_apps);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, agent_gpms);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d1);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d2);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d3);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d4);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d5);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d6);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d7);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, d8);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, cc_image);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, ghub_image);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, gauth_image);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, gctrl_image);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, gpms_image);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, agent_image);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, apps_view);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, apps_list);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, log_button);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, security_framework_notebook);
  gtk_widget_class_bind_template_child (widget_class, CcSecurityFrameworkPanel, no_security_framework_label);
}

static void
panel_value_init (CcSecurityFrameworkPanel *self)
{
  GDateTime *local_time;

  self->fp = NULL;
  self->policy_reload_flag = FALSE;
  self->event_cnt = 0;
  self->log_start = 0;
  self->log_end = -1;
  self->log_cnt = 0;
  self->scene = SCENE_IDLE;
  self->init_num = 0;
  self->apps_num = 0;
  self->full_log = _("\n\t*** Security Framework Panel Activated. ***\n\n");
  local_time = g_date_time_new_now_local ();
  self->tailing_file = g_strconcat (LOG_DIRECTORY, LOG_FILE_PREFIX, "-", g_date_time_format (local_time, "%F"), ".log", NULL);
  g_date_time_unref (local_time);
}

static void
cc_security_framework_panel_init (CcSecurityFrameworkPanel *self)
{
  int module;
  GtkWidget *event_box;
  PangoAttrList *pg_attr_list;
  PangoAttribute *pg_attr;
  char *ret;
  int r, i, j, k, d;
  FILE* fp = NULL;
  char buf[255] = {0, };
  char key[255] = {0, };
  char val[255] = {0, };
  gboolean deactivated = TRUE;

  g_resources_register (cc_security_framework_get_resource ());

  gtk_widget_init_template (GTK_WIDGET (self));
  panel_value_init (self);

  if (access (LSF_CONF, R_OK))
    gtk_notebook_set_current_page (GTK_NOTEBOOK (self->security_framework_notebook), LSF_NOT_FOUND_PAGE);
  else
  {
    fp = fopen (LSF_CONF, "r");
    while (fgets (buf, sizeof (buf), fp))
    {
      for (i=j=k=d=0; buf[i]; i++)
      {
        if (buf[i] == ' ' || buf[i] == '\n')
          continue;

        if (d)
          val[k++] = buf[i];
        else if (buf[i] == '=')
          d = TRUE;
        else
          key[j++] = buf[i];
      }
      key[j]=val[k]='\0';
      if (!d)
        continue;
      
      if (strcmp (key, "control_center_use") == 0)
      {
        if (strcmp (val, "yes") == 0)
          deactivated = FALSE;
        break;
      }
    }
    fclose (fp);
    if (deactivated)
    {
      gtk_notebook_set_current_page (GTK_NOTEBOOK (self->security_framework_notebook), LSF_NOT_FOUND_PAGE);
      gtk_label_set_text (GTK_LABEL (self->no_security_framework_label), _("Security Framework Panel Deactivated."));
    }
  }

  if (!deactivated)
  {
    gtk_notebook_set_current_page (GTK_NOTEBOOK (self->security_framework_notebook), LSF_PAGE);
    lsf_user_data_t app_data;
    r = lsf_auth (&app_data, CC_PASSPHRASE);
    if (r == LSF_AUTH_STAT_OK)
    {
      lsf_panel_symm_key = g_strdup (app_data.symm_key);
      lsf_panel_access_token = g_strdup (app_data.access_token);
      ret = dbus_message_sender (GINT_TO_POINTER (GET_CONFIG));
      self->topology = get_topology (ret);
    }
    modules_state_updater (self);
    draw_lines (self);

    self->fp = fopen (self->tailing_file, "r");
    if (self->fp != NULL)
    {
      fseek (self->fp, 0, SEEK_END);
      self->fpos = ftell (self->fp);
    }

    self->agent_menu = gtk_menu_new ();
    set_menu_items (self, AGENT);

    self->gctrl_menu = gtk_menu_new ();
    set_menu_items (self, GCTRL);

    self->log_label = gtk_label_new ("");

    g_signal_connect (G_OBJECT (self->d1),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d2),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d3),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d4),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d5),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d6),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d7),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->d8),
                      "draw",
                      G_CALLBACK (draw_vertical_bar),
                      self);
    g_signal_connect (G_OBJECT (self->ghub_cc),
                      "draw",
                      G_CALLBACK (draw_conn_ghub_cc),
                      self);
    g_signal_connect (G_OBJECT (self->ghub_gauth),
                      "draw",
                      G_CALLBACK (draw_conn_ghub_gauth),
                      self);
    g_signal_connect (G_OBJECT (self->ghub_gctrl),
                      "draw",
                      G_CALLBACK (draw_conn_ghub_gctrl),
                      self);
    g_signal_connect (G_OBJECT (self->ghub_apps),
                      "draw",
                      G_CALLBACK (draw_conn_ghub_apps),
                      self);
    g_signal_connect (G_OBJECT (self->agent_gpms),
                      "draw",
                      G_CALLBACK (draw_conn_agent_gpms),
                      self);
    g_signal_connect (G_OBJECT (self->ghub_agent),
                      "draw",
                      G_CALLBACK (draw_conn_ghub_agent),
                      self);
    g_signal_connect (G_OBJECT (self->gpms_button),
                      "button-press-event",
                      G_CALLBACK (gpms_cell_clicked),
                      self);
    g_signal_connect (G_OBJECT (self->agent_button),
                      "button-press-event",
                      G_CALLBACK (agent_cell_clicked),
                      self);
    g_signal_connect (G_OBJECT (self->gctrl_button),
                      "button-press-event",
                      G_CALLBACK (gctrl_cell_clicked),
                      self);
    g_signal_connect (G_OBJECT (self->log_button),
                      "clicked",
                      G_CALLBACK (log_button_clicked),
                      self);
  }
}

GtkWidget *
cc_security_framework_panel_new (void)
{
  return g_object_new (CC_TYPE_SECURITY_FRAMEWORK_PANEL,
                       NULL);
}
