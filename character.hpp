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

#ifndef CHARACTER_HPP
#define CHARACTER_HPP

/*
 * One character (PC or NPC).
 */
class Character {
public:
  Character *master;
  Character *leader;
  Character *fighting;
  Character *reply;
  SPEC_FUN *spec_fun;
  MobPrototype *pIndexData;
  Descriptor *desc;
  std::list<Affect *> affected;
  Note *pnote;
  std::list<Object *> carrying;
  Room *in_room;
  Room *was_in_room;
  PCData *pcdata;
  std::string name;
  std::string short_descr;
  std::string long_descr;
  std::string description;
  std::string prompt;
  sh_int sex;
  sh_int klass;
  sh_int race;
  int level;
  sh_int trust;
  bool wizbit;
  int played;
  time_t logon;
  time_t save_time;
  time_t last_note;
  sh_int timer;
  int wait;
  int hit;
  int max_hit;
  int mana;
  int max_mana;
  int move;
  int max_move;
  int gold;
  int exp;
  int actflags;
  int affected_by;
  sh_int position;
  sh_int practice;
  sh_int carry_weight;
  sh_int carry_number;
  sh_int saving_throw;
  sh_int alignment;
  sh_int hitroll;
  sh_int damroll;
  sh_int armor;
  sh_int wimpy;
  sh_int deaf;
  MobProgramActList *mpact;        /* Used by MOBprogram */
  int mpactnum;                 /* Used by MOBprogram */

  Character::Character();
  Character::~Character();

  void do_areas(std::string argument);
  void do_memory(std::string argument);
  void do_kill(std::string argument);
  void do_murde(std::string argument);
  void do_murder(std::string argument);
  void do_backstab(std::string argument);
  void do_flee(std::string argument);
  void do_rescue(std::string argument);
  void do_kick(std::string argument);
  void do_disarm(std::string argument);
  void do_sla(std::string argument);
  void do_slay(std::string argument);
  void do_cast(std::string argument);
  void do_note(std::string argument);
  void do_auction(std::string argument);
  void do_chat(std::string argument);
  void do_music(std::string argument);
  void do_question(std::string argument);
  void do_answer(std::string argument);
  void do_shout(std::string argument);
  void do_yell(std::string argument);
  void do_immtalk(std::string argument);
  void do_say(std::string argument);
  void do_tell(std::string argument);
  void do_reply(std::string argument);
  void do_emote(std::string argument);
  void do_bug(std::string argument);
  void do_idea(std::string argument);
  void do_typo(std::string argument);
  void do_rent(std::string argument);
  void do_qui(std::string argument);
  void do_quit(std::string argument);
  void do_save(std::string argument);
  void do_follow(std::string argument);
  void do_order(std::string argument);
  void do_group(std::string argument);
  void do_split(std::string argument);
  void do_gtell(std::string argument);
  void do_look(std::string argument);
  void do_examine(std::string argument);
  void do_exits(std::string argument);
  void do_score(std::string argument);
  void do_time(std::string argument);
  void do_weather(std::string argument);
  void do_help(std::string argument);
  void do_who(std::string argument);
  void do_inventory(std::string argument);
  void do_equipment(std::string argument);
  void do_compare(std::string argument);
  void do_credits(std::string argument);
  void do_where(std::string argument);
  void do_consider(std::string argument);
  void do_title(std::string argument);
  void do_description(std::string argument);
  void do_report(std::string argument);
  void do_practice(std::string argument);
  void do_wimpy(std::string argument);
  void do_password(std::string argument);
  void do_socials(std::string argument);
  void do_commands(std::string argument);
  void do_channels(std::string argument);
  void do_config(std::string argument);
  void do_wizlist(std::string argument);
  void do_spells(std::string argument);
  void do_slist(std::string argument);
  void do_autoexit(std::string argument);
  void do_autoloot(std::string argument);
  void do_autosac(std::string argument);
  void do_blank(std::string argument);
  void do_brief(std::string argument);
  void do_combine(std::string argument);
  void do_pagelen(std::string argument);
  void do_prompt(std::string argument);
  void do_auto(std::string argument);
  void do_north(std::string argument);
  void do_east(std::string argument);
  void do_south(std::string argument);
  void do_west(std::string argument);
  void do_up(std::string argument);
  void do_down(std::string argument);
  void do_open(std::string argument);
  void do_close(std::string argument);
  void do_lock(std::string argument);
  void do_unlock(std::string argument);
  void do_pick(std::string argument);
  void do_stand(std::string argument);
  void do_rest(std::string argument);
  void do_sleep(std::string argument);
  void do_wake(std::string argument);
  void do_sneak(std::string argument);
  void do_hide(std::string argument);
  void do_visible(std::string argument);
  void do_recall(std::string argument);
  void do_train(std::string argument);
  void do_get(std::string argument);
  void do_put(std::string argument);
  void do_drop(std::string argument);
  void do_give(std::string argument);
  void do_fill(std::string argument);
  void do_drink(std::string argument);
  void do_eat(std::string argument);
  void do_wear(std::string argument);
  void do_remove(std::string argument);
  void do_sacrifice(std::string argument);
  void do_quaff(std::string argument);
  void do_recite(std::string argument);
  void do_brandish(std::string argument);
  void do_zap(std::string argument);
  void do_steal(std::string argument);
  void do_buy(std::string argument);
  void do_list(std::string argument);
  void do_sell(std::string argument);
  void do_value(std::string argument);
  void do_wizhelp(std::string argument);
  void do_bamfin(std::string argument);
  void do_bamfout(std::string argument);
  void do_deny(std::string argument);
  void do_disconnect(std::string argument);
  void do_pardon(std::string argument);
  void do_echo(std::string argument);
  void do_recho(std::string argument);
  void do_transfer(std::string argument);
  void do_at(std::string argument);
  void do_goto(std::string argument);
  void do_rstat(std::string argument);
  void do_ostat(std::string argument);
  void do_mstat(std::string argument);
  void do_mfind(std::string argument);
  void do_ofind(std::string argument);
  void do_mwhere(std::string argument);
  void do_reboo(std::string argument);
  void do_reboot(std::string argument);
  void do_shutdow(std::string argument);
  void do_shutdown(std::string argument);
  void do_switch(std::string argument);
  void do_return(std::string argument);
  void do_mload(std::string argument);
  void do_oload(std::string argument);
  void do_purge(std::string argument);
  void do_advance(std::string argument);
  void do_trust(std::string argument);
  void do_restore(std::string argument);
  void do_freeze(std::string argument);
  void do_noemote(std::string argument);
  void do_notell(std::string argument);
  void do_silence(std::string argument);
  void do_peace(std::string argument);
  void do_ban(std::string argument);
  void do_allow(std::string argument);
  void do_wizlock(std::string argument);
  void do_slookup(std::string argument);
  void do_sset(std::string argument);
  void do_mset(std::string argument);
  void do_oset(std::string argument);
  void do_rset(std::string argument);
  void do_users(std::string argument);
  void do_force(std::string argument);
  void do_invis(std::string argument);
  void do_holylight(std::string argument);
  void do_wizify(std::string argument);
  void do_owhere(std::string argument);
  void do_mpstat(std::string argument);
  void do_mpasound(std::string argument);
  void do_mpkill(std::string argument);
  void do_mpjunk(std::string argument);
  void do_mpechoaround(std::string argument);
  void do_mpechoat(std::string argument);
  void do_mpecho(std::string argument);
  void do_mpmload(std::string argument);
  void do_mpoload(std::string argument);
  void do_mppurge(std::string argument);
  void do_mpgoto(std::string argument);
  void do_mpat(std::string argument);
  void do_mptransfer(std::string argument);
  void do_mpforce(std::string argument);

  void spell_acid_blast(int sn, int level, void *vo);
  void spell_armor(int sn, int level, void *vo);
  void spell_bless(int sn, int level, void *vo);
  void spell_blindness(int sn, int level, void *vo);
  void spell_burning_hands(int sn, int level, void *vo);
  void spell_call_lightning(int sn, int level, void *vo);
  void spell_cause_light(int sn, int level, void *vo);
  void spell_cause_critical(int sn, int level, void *vo);
  void spell_cause_serious(int sn, int level, void *vo);
  void spell_change_sex(int sn, int level, void *vo);
  void spell_charm_person(int sn, int level, void *vo);
  void spell_chill_touch(int sn, int level, void *vo);
  void spell_colour_spray(int sn, int level, void *vo);
  void spell_continual_light(int sn, int level, void *vo);
  void spell_control_weather(int sn, int level, void *vo);
  void spell_create_food(int sn, int level, void *vo);
  void spell_create_spring(int sn, int level, void *vo);
  void spell_create_water(int sn, int level, void *vo);
  void spell_cure_blindness(int sn, int level, void *vo);
  void spell_cure_critical(int sn, int level, void *vo);
  void spell_cure_light(int sn, int level, void *vo);
  void spell_cure_poison(int sn, int level, void *vo);
  void spell_cure_serious(int sn, int level, void *vo);
  void spell_curse(int sn, int level, void *vo);
  void spell_detect_evil(int sn, int level, void *vo);
  void spell_detect_hidden(int sn, int level, void *vo);
  void spell_detect_invis(int sn, int level, void *vo);
  void spell_detect_magic(int sn, int level, void *vo);
  void spell_detect_poison(int sn, int level, void *vo);
  void spell_dispel_magic(int sn, int level, void *vo);
  void spell_dispel_evil(int sn, int level, void *vo);
  void spell_earthquake(int sn, int level, void *vo);
  void spell_enchant_weapon(int sn, int level, void *vo);
  void spell_energy_drain(int sn, int level, void *vo);
  void spell_fireball(int sn, int level, void *vo);
  void spell_flamestrike(int sn, int level, void *vo);
  void spell_faerie_fire(int sn, int level, void *vo);
  void spell_faerie_fog(int sn, int level, void *vo);
  void spell_fly(int sn, int level, void *vo);
  void spell_gate(int sn, int level, void *vo);
  void spell_general_purpose(int sn, int level, void *vo);
  void spell_giant_strength(int sn, int level, void *vo);
  void spell_harm(int sn, int level, void *vo);
  void spell_heal(int sn, int level, void *vo);
  void spell_high_explosive(int sn, int level, void *vo);
  void spell_identify(int sn, int level, void *vo);
  void spell_infravision(int sn, int level, void *vo);
  void spell_invis(int sn, int level, void *vo);
  void spell_know_alignment(int sn, int level, void *vo);
  void spell_lightning_bolt(int sn, int level, void *vo);
  void spell_locate_object(int sn, int level, void *vo);
  void spell_magic_missile(int sn, int level, void *vo);
  void spell_mass_invis(int sn, int level, void *vo);
  void spell_null(int sn, int level, void *vo);
  void spell_pass_door(int sn, int level, void *vo);
  void spell_poison(int sn, int level, void *vo);
  void spell_protection(int sn, int level, void *vo);
  void spell_refresh(int sn, int level, void *vo);
  void spell_remove_curse(int sn, int level, void *vo);
  void spell_sanctuary(int sn, int level, void *vo);
  void spell_shield(int sn, int level, void *vo);
  void spell_shocking_grasp(int sn, int level, void *vo);
  void spell_sleep(int sn, int level, void *vo);
  void spell_stone_skin(int sn, int level, void *vo);
  void spell_summon(int sn, int level, void *vo);
  void spell_teleport(int sn, int level, void *vo);
  void spell_ventriloquate(int sn, int level, void *vo);
  void spell_weaken(int sn, int level, void *vo);
  void spell_word_of_recall(int sn, int level, void *vo);
  void spell_acid_breath(int sn, int level, void *vo);
  void spell_fire_breath(int sn, int level, void *vo);
  void spell_frost_breath(int sn, int level, void *vo);
  void spell_gas_breath(int sn, int level, void *vo);
  void spell_lightning_breath(int sn, int level, void *vo);

  int is_npc();
  bool is_awake();
  bool is_good();
  bool is_evil();
  bool is_neutral();
  bool is_affected(int flg);
  int get_ac();
  int get_hitroll();
  int get_damroll();
  int get_curr_str();
  int get_curr_int();
  int get_curr_wis();
  int get_curr_dex();
  int get_curr_con();
  int get_age();
  int can_carry_n();
  int can_carry_w();
  int get_trust();
  bool is_immortal();
  bool is_hero();
  int is_outside();
  void wait_state(int npulse);
  int mana_cost(int sn);
  bool saves_spell (int lvl);
  std::string describe_to (Character* looker);
  Object * get_eq_char (int iWear);
  void affect_modify (Affect * paf, bool fAdd);
  bool can_see (Character * victim);
  bool can_see_obj (Object * obj);
  void unequip_char (Object * obj);
  void char_from_room ();
  void char_to_room (Room * pRoomIndex);
  void send_to_char (const std::string & txt);
  void interpret (std::string argument);
  bool check_social (const std::string & command, const std::string & argument);
  void set_title (const std::string & title);
  bool is_switched ();
  void advance_level ();
  bool mp_commands ();
  void gain_exp(int gain);
  int hit_gain ();
  int mana_gain ();
  int move_gain ();
  void add_follower (Character * master);
  void stop_follower();
  void die_follower();
  void update_pos ();
  void set_fighting (Character * victim);
  bool check_blind ();
  bool has_key (int key);
  void affect_to_char (Affect * paf);
  void affect_remove (Affect * paf);
  void affect_strip (int sn);
  bool has_affect (int sn);
  void affect_join (Affect * paf);
  bool remove_obj (int iWear, bool fReplace);
  void wear_obj (Object * obj, bool fReplace);
  void equip_char (Object * obj, int iWear);
  void act (const std::string & format, const void *arg1, const void *arg2, int type);
  bool can_drop_obj (Object * obj);
  Object * get_obj_wear (const std::string & argument);
  Object * get_obj_carry (const std::string & argument);
  Object * get_obj_here (const std::string & argument);
  void fwrite_char (std::ofstream & fp);
  void append_file (char *file, const std::string & str);
  Character * get_char_room (const std::string & argument);
  Character * get_char_world (const std::string & argument);
  Object * get_obj_list (const std::string & argument, std::list<Object *> & list);
  Object * get_obj_world (const std::string & argument);
  void save_char_obj ();
  void fread_char (std::ifstream & fp);
  void gain_condition (int iCond, int value);
  void stop_fighting (bool fBoth);
  int find_door (const std::string & arg);
  void get_obj (Object * obj, Object * container);
  void extract_char (bool fPull);
  void stop_idling ();
  void show_list_to_char (std::list<Object *> & list, bool fShort, bool fShowNothing);
  void show_char_to_char_0 (Character * victim);
  void show_char_to_char_1 (Character * victim);
  void show_char_to_char (std::list<Character *> & list);
  void move_char (int door);


};

#endif // CHARACTER_HPP
