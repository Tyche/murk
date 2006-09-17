/***************************************************************************
 *  Original Diku Mud copyright (C) 1990, 1991 by Sebastian Hammer,        *
 *  Michael Seifert, Hans Henrik St{rfeldt, Tom Madsen, and Katja Nyboe.   *
 *                                                                         *
 *  Merc Diku Mud improvments copyright (C) 1992, 1993 by Michael          *
 *  Chastain, Michael Quan, and Mitchell Tse.                              *
 *                                                                         *
 *  In order to use any part of this Merc Diku Mud, you must comply with   *
 *  both the original Diku license in 'license.diku' as well the Merc      *
 *  license in 'license.merc'.  In particular, you may not remove either   *
 *  of these copyright notices.                                            *
 *                                                                         *
 *  Much time and thought has gone into this software and you are          *
 *  benefitting.  We hope that you share your changes too.  What goes      *
 *  around, comes around.                                                  *
 ***************************************************************************/

/*
 MurkMUD++ - A Windows compatible, C++ compatible Merc 2.2 Mud.

 \author Jon A. Lambert
 \date 08/30/2006
 \version 1.4
 \remarks
  This source code copyright (C) 2005, 2006 by Jon A. Lambert
  All rights reserved.

  Use governed by the MurkMUD++ public license found in license.murk++
*/

#ifndef MOBPROTO_HPP
#define MOBPROTO_HPP

/*
 * Prototype for a mob.
 * This is the in-memory version of #MOBILES.
 */
class MobPrototype {
public:
  static int top_mob;
  SPEC_FUN *spec_fun;
  Shop *pShop;
  std::string player_name;
  std::string short_descr;
  std::string long_descr;
  std::string description;
  sh_int vnum;
  int count;
  int killed;
  sh_int sex;
  int level;
  int actflags;
  int affected_by;
  sh_int alignment;
  MobProgram *mobprogs;         /* Used by MOBprogram */
  int progtypes;                /* Used by MOBprogram */

  MobPrototype();
  Character * create_mobile ();
};

#endif // MOBPROTO_HPP

