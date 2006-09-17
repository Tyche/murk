/***************************************************************************
 *  Original Diku Mud copyright (C) 1990, 1991 by Sebastian Hammer,        *
 *  Michael Seifert, Hans Henrik St{rfeldt, Tom Madsen, and Katja Nyboe.   *
 *                                                                         *
 *  Merc Diku Mud improvments copyright (C) 1992, 1993 by Michael          *
 *  Chastain, Michael Quan, and Mitchell Tse.                              *
 *                                                                         *
 *  In order to use any part of this Merc Diku Mud, you must comply with   *
 *  both the original Diku license in 'license.doc' as well the Merc       *
 *  license in 'license.txt'.  In particular, you may not remove either of *
 *  these copyright notices.                                               *
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

#ifndef GLOBALS_HPP
#define GLOBALS_HPP

// Global variables
extern std::list<Area *> area_list;
extern Area *area_last;
extern std::list<Ban *> ban_list;
extern std::list<Character *> char_list;
extern std::list<Descriptor *> descriptor_list;       /* All open descriptors     */
extern std::list<Note *> note_list;
extern std::list<Object *> object_list;
extern std::list<Shop *> shop_list;

// These iterators used on loops where the next iterator can be invalidated
// because of a nested method that erases an object in the list.
extern CharIter deepchnext, deeprmnext;
extern ObjIter deepobnext;
extern DescIter deepdenext;
//bool character_invalidated = false;  // This is set in Mprogs if we

extern std::map<int, MobPrototype *> mob_table;
extern std::map<int, ObjectPrototype *> obj_table;
extern std::map<int, Room *> room_table;

extern struct cmd_type cmd_table[];
extern struct skill_type skill_table[MAX_SKILL];
extern struct class_type class_table[CLASS_MAX];
extern struct liq_type liq_table[LIQ_MAX];
extern const std::string where_name[];
extern std::string month_name[];
extern std::string day_name[];
extern struct time_info_data time_info;
extern struct weather_data weather_info;

extern struct int_app_type int_app[26];
extern struct str_app_type str_app[26];
extern struct dex_app_type dex_app[26];
extern struct con_app_type con_app[26];
extern struct wis_app_type wis_app[26];

extern bool merc_down;
extern bool wizlock;
extern std::string str_boot_time;
extern time_t current_time;            /* Time of this pulse       */
extern sqlite3 *database;
extern bool MOBtrigger;
extern std::ifstream * fpArea;
extern std::string strArea;

extern sh_int gsn_backstab;
extern sh_int gsn_dodge;
extern sh_int gsn_hide;
extern sh_int gsn_peek;
extern sh_int gsn_pick_lock;
extern sh_int gsn_sneak;
extern sh_int gsn_steal;

extern sh_int gsn_disarm;
extern sh_int gsn_enhanced_damage;
extern sh_int gsn_kick;
extern sh_int gsn_parry;
extern sh_int gsn_rescue;
extern sh_int gsn_second_attack;
extern sh_int gsn_third_attack;

extern sh_int gsn_blindness;
extern sh_int gsn_charm_person;
extern sh_int gsn_curse;
extern sh_int gsn_invis;
extern sh_int gsn_mass_invis;
extern sh_int gsn_poison;
extern sh_int gsn_sleep;

extern std::string target_name;
extern std::string dir_name[];
extern sh_int rev_dir[];
extern Object *rgObjNest[MAX_NEST];

// Global functions
extern ObjectPrototype *get_obj_index (int vnum);
extern Room *get_room_index (int vnum);
extern MobPrototype *get_mob_index (int vnum);
extern int skill_lookup (const std::string & name);

#endif
