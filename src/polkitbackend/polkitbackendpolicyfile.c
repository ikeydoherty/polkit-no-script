/*
 * Copyright (C) 2017 Ikey Doherty
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Ikey Doherty <ikey@solus-project.com>
 */

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polkitbackendpolicyfile.h"

/**
 * Permanently correct section for defining:
 * Rules=
 * AdminRules=
 */
#define POLICY_SECTION "Policy"

/**
 * Action ID to match all possible IDs
 * Useful for "SubjectUser=" matches
 */
#define POLICY_MATCH_ALL "*"

/**
 * We'll swap "%wheel% for the wheel group configured at build time so that
 * other policies can easily reference them.
 */
#define POLICY_MATCH_WHEEL "%wheel%"

/**
 * TODO: Take from a configure time option
 */
#define POLICY_WHEEL_USER "wheel"

static gboolean policy_file_load_rules (GKeyFile *keyfile,
                                        const gchar *section, Policy **target);
static PolkitResponse policy_string_to_result (const gchar *inp);

PolicyFile *
policy_file_new_from_path (const char *path)
{
  g_autoptr (GKeyFile) keyf = NULL;
  g_autoptr (GError) err = NULL;
  PolicyFile *ret = NULL;

  keyf = g_key_file_new ();
  if (!g_key_file_load_from_file (keyf, path, G_KEY_FILE_NONE, &err))
    {
      fprintf (stderr, "Failed to load file: %s\n", err->message);
      return NULL;
    }

  ret = g_new0 (PolicyFile, 1);

  if (!policy_file_load_rules (keyf, "Rules", &ret->rules.normal))
    {
      policy_file_free (ret);
      return NULL;
    }

  if (!policy_file_load_rules (keyf, "AdminRules", &ret->rules.admin))
    {
      policy_file_free (ret);
      return NULL;
    }

  return ret;
}

static void
policy_free (Policy *policy)
{
  if (!policy)
    {
      return;
    }
  g_clear_pointer (&policy->next, policy_free);
  g_clear_pointer (&policy->id, g_free);
  g_clear_pointer (&policy->actions, g_strfreev);
  g_clear_pointer (&policy->action_contains, g_strfreev);
  g_clear_pointer (&policy->unix_groups, g_strfreev);
  g_clear_pointer (&policy->unix_names, g_strfreev);
  g_clear_pointer (&policy->net_groups, g_strfreev);
  g_free (policy);
}

void
policy_file_free (PolicyFile *file)
{
  if (!file)
    {
      return;
    }
  g_clear_pointer (&file->next, policy_file_free);
  g_clear_pointer (&file->rules.admin, policy_free);
  g_clear_pointer (&file->rules.normal, policy_free);
  g_free (file);
}

/**
 * Attempt to load a policy from the given section id and keyfile
 */
static Policy *
policy_load (GKeyFile *file, const gchar *section_id)
{
  Policy *policy = NULL;
  gsize n_segments = 0;
  g_autoptr (GError) err = NULL;

  if (!g_key_file_has_group (file, section_id))
    {
      fprintf (stderr, "Missing rule: '%s'\n", section_id);
      return NULL;
    }

  policy = g_new0 (Policy, 1);
  policy->id = g_strdup (section_id);

  /* Load Action IDs */
  if (g_key_file_has_key (file, section_id, "Actions", NULL))
    {
      policy->actions = g_key_file_get_string_list (
          file, section_id, "Actions", &n_segments, &err);
      if (err)
        {
          goto handle_err;
        }
      policy->n_actions = n_segments;
      policy->constraints |= PF_CONSTRAINT_ACTIONS;
      n_segments = 0;
    }

  /* Load ActionContains IDs */
  if (g_key_file_has_key (file, section_id, "ActionContains", NULL))
    {
      policy->action_contains = g_key_file_get_string_list (
          file, section_id, "ActionContains", &n_segments, &err);
      if (err)
        {
          goto handle_err;
        }
      policy->n_action_contains = n_segments;
      policy->constraints |= PF_CONSTRAINT_ACTION_CONTAINS;
      n_segments = 0;
    }

  /* Are specific unix groups needed? */
  if (g_key_file_has_key (file, section_id, "InUnixGroups", NULL))
    {
      policy->unix_groups = g_key_file_get_string_list (
          file, section_id, "InUnixGroups", &n_segments, &err);
      if (err)
        {
          goto handle_err;
        }
      policy->n_unix_groups = n_segments;
      policy->constraints |= PF_CONSTRAINT_UNIX_GROUPS;
      n_segments = 0;
    }

  /* Are specific net groups needed? */
  if (g_key_file_has_key (file, section_id, "InNetGroups", NULL))
    {
      policy->net_groups = g_key_file_get_string_list (
          file, section_id, "InNetGroups", &n_segments, &err);
      if (err)
        {
          goto handle_err;
        }
      policy->n_net_groups = n_segments;
      policy->constraints |= PF_CONSTRAINT_NET_GROUPS;
      n_segments = 0;
    }

  /* Find out the response type */
  if (g_key_file_has_key (file, section_id, "Result", NULL))
    {
      g_autofree gchar *result
          = g_key_file_get_string (file, section_id, "Result", &err);
      if (err)
        {
          goto handle_err;
        }
      policy->response = policy_string_to_result (g_strstrip (result));
      if (policy->response == PK_RESPONSE_UNHANDLED)
        {
          fprintf (stderr, "invalid 'Result': '%s'\n", result);
          goto handle_err;
        }
      policy->constraints |= PF_CONSTRAINT_RESULT;
    }

  /* Find out the inverse response type */
  if (g_key_file_has_key (file, section_id, "ResultInverse", NULL))
    {
      g_autofree gchar *result
          = g_key_file_get_string (file, section_id, "ResultInverse", &err);
      if (err)
        {
          goto handle_err;
        }
      policy->response_inverse = policy_string_to_result (g_strstrip (result));
      if (policy->response == PK_RESPONSE_UNHANDLED)
        {
          fprintf (stderr, "invalid 'ResultInverse': '%s'\n", result);
          goto handle_err;
        }
      policy->constraints |= PF_CONSTRAINT_RESULT_INVERSE;
    }

  /* Match unix usernames */
  if (g_key_file_has_key (file, section_id, "InUserNames", NULL))
    {
      policy->unix_names = g_key_file_get_string_list (
          file, section_id, "InUserNames", &n_segments, &err);
      if (err)
        {
          goto handle_err;
        }
      policy->n_unix_names = n_segments;
      policy->constraints |= PF_CONSTRAINT_UNIX_NAMES;
      n_segments = 0;
    }

  /* Match active */
  if (g_key_file_has_key (file, section_id, "SubjectActive", NULL))
    {
      policy->require_active
          = g_key_file_get_boolean (file, section_id, "SubjectActive", &err);
      if (err)
        {
          goto handle_err;
        }
      policy->constraints |= PF_CONSTRAINT_SUBJECT_ACTIVE;
    }

  /* Match local */
  if (g_key_file_has_key (file, section_id, "SubjectLocal", NULL))
    {
      policy->require_local
          = g_key_file_get_boolean (file, section_id, "SubjectLocal", &err);
      if (err)
        {
          goto handle_err;
        }
      policy->constraints |= PF_CONSTRAINT_SUBJECT_LOCAL;
    }

  return policy;

handle_err:

  /* Print error.. */
  fprintf (stderr, "policy_load(): error: %s\n", err->message);

  policy_free (policy);
  return NULL;
}

/**
 * Attempt to load rules from the named section within the key file
 */
static gboolean
policy_file_load_rules (GKeyFile *keyfile, const gchar *section,
                        Policy **target)
{
  gchar **sections = NULL;
  gsize n_sections = 0;
  g_autoptr (GError) err = NULL;
  Policy *last = NULL;

  sections = g_key_file_get_string_list (keyfile, POLICY_SECTION, section,
                                         &n_sections, &err);
  if (err)
    {
      fprintf (stderr, "Failed to get sections: %s\n", err->message);
      return FALSE;
    }

  fprintf (stderr, "Got %d sections\n", (int)n_sections);

  /* Attempt to load each rule now */
  for (gsize i = 0; i < n_sections; i++)
    {
      Policy *p = NULL;

      p = policy_load (keyfile, g_strstrip (sections[i]));
      if (!p)
        {
          g_strfreev (sections);
          return FALSE;
        }
      if (last)
        {
          last->next = p;
          last = p;
        }
      else
        {
          last = *target = p;
        }
    }

  g_strfreev (sections);

  return TRUE;
}

/**
 * Quickly turn the string into a usable internal response
 */
static PolkitResponse
policy_string_to_result (const gchar *inp)
{
  g_autofree gchar *comparison = g_ascii_strdown (inp, -1);

  if (g_str_equal (comparison, "no"))
    {
      return PK_RESPONSE_NO;
    }
  else if (g_str_equal (comparison, "yes"))
    {
      return PK_RESPONSE_YES;
    }
  else if (g_str_equal (comparison, "auth_self"))
    {
      return PK_RESPONSE_AUTH_SELF;
    }
  else if (g_str_equal (comparison, "auth_self_keep"))
    {
      return PK_RESPONSE_AUTH_SELF_KEEP;
    }
  else if (g_str_equal (comparison, "auth_admin"))
    {
      return PK_RESPONSE_AUTH_ADMIN;
    }
  else if (g_str_equal (comparison, "auth_admin_keep"))
    {
      return PK_RESPONSE_AUTH_ADMIN_KEEP;
    }
  else
    {
      return PK_RESPONSE_UNHANDLED;
    }
}
