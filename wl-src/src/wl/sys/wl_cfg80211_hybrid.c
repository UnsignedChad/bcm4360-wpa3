/*
 * Linux-specific portion of Broadcom 802.11abg Networking Device Driver
 * cfg80211 interface
 *
 * Copyright (C) 2015, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: wl_cfg80211.c,v 1.1.6.4 2011-02-11 00:22:09 $
 */

#if defined(USE_CFG80211)

#define LINUX_PORT
#include <typedefs.h>
#include <linuxver.h>
#include <osl.h>

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/ieee80211.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <net/cfg80211.h>
#include <linux/nl80211.h>
#include <net/rtnetlink.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <wlioctl.h>
#include <proto/802.11.h>
#include <wl_cfg80211_hybrid.h>
#include <wl_linux.h>

#define EVENT_TYPE(e) dtoh32((e)->event_type)
#define EVENT_FLAGS(e) dtoh16((e)->flags)
#define EVENT_STATUS(e) dtoh32((e)->status)

#ifdef BCMDBG
u32 wl_dbg_level = WL_DBG_ERR | WL_DBG_INFO;
#else
u32 wl_dbg_level = WL_DBG_ERR;
#endif

static s32 wl_cfg80211_change_iface(struct wiphy *wiphy, struct net_device *ndev,
           enum nl80211_iftype type,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
           u32 *flags,
#endif
	   struct vif_params *params);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
static s32
wl_cfg80211_scan(struct wiphy *wiphy,
                 struct cfg80211_scan_request *request);
#else
static s32 wl_cfg80211_scan(struct wiphy *wiphy, struct net_device *ndev,
           struct cfg80211_scan_request *request);
#endif
/* cfg80211 op signature changes tracked by the LINUX_VERSION_CODE guards below
 * (verified by building against 6.12, 6.14, 6.17, 7.0, 7.1, 7.2 and 7.3 headers):
 *   6.17  set_wiphy_params/set_tx_power/get_tx_power gained `int radio_idx`
 *   7.1   add_key/del_key/get_key/get_station take a wireless_dev instead of a net_device
 *   7.3   mgmt_tx receives the cookie by value (cfg80211 now assigns it) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, int radio_idx, u32 changed);
#else
static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed);
#endif
static s32 wl_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *dev,
           struct cfg80211_ibss_params *params);
static s32 wl_cfg80211_leave_ibss(struct wiphy *wiphy, struct net_device *dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
static s32 wl_cfg80211_get_station(struct wiphy *wiphy,
           struct net_device *dev, u8 *mac, struct station_info *sinfo);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
static s32 wl_cfg80211_get_station(struct wiphy *wiphy,
           struct wireless_dev *wdev, const u8 *mac, struct station_info *sinfo);
#else
static s32 wl_cfg80211_get_station(struct wiphy *wiphy,
           struct net_device *dev, const u8 *mac, struct station_info *sinfo);
#endif

static s32 wl_cfg80211_set_power_mgmt(struct wiphy *wiphy,
           struct net_device *dev, bool enabled, s32 timeout);
static int wl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
           struct cfg80211_connect_params *sme);
static s32 wl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev, u16 reason_code);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, int radio_idx,
                         enum nl80211_tx_power_setting type, s32 mbm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
                         enum nl80211_tx_power_setting type, s32 mbm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static s32 wl_cfg80211_set_tx_power(struct wiphy *wiphy,
           enum nl80211_tx_power_setting type, s32 mbm);
#else
static s32 wl_cfg80211_set_tx_power(struct wiphy *wiphy,
           enum tx_power_setting type, s32 mbm);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, int radio_idx, unsigned int link_id, s32 *dbm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, u32 /*link_id*/, s32 *dbm);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, s32 *dbm);
#else
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, s32 *dbm);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static s32 wl_cfg80211_config_default_key(struct wiphy *wiphy,
           struct net_device *dev, int link_id, u8 key_idx, bool unicast,
           bool multicast);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
static s32 wl_cfg80211_config_default_key(struct wiphy *wiphy,
           struct net_device *dev, u8 key_idx, bool unicast, bool multicast);
#else
static s32 wl_cfg80211_config_default_key(struct wiphy *wiphy,
           struct net_device *dev, u8 key_idx);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
static s32 wl_cfg80211_add_key(struct wiphy *wiphy, struct wireless_dev *wdev,
           int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
           struct key_params *params);
static s32 wl_cfg80211_del_key(struct wiphy *wiphy, struct wireless_dev *wdev,
           int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr);
static s32 wl_cfg80211_get_key(struct wiphy *wiphy, struct wireless_dev *wdev,
           int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
           void *cookie,
           void (*callback) (void *cookie, struct key_params *params));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static s32 wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
           int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
           struct key_params *params);
static s32 wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
           int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr);
static s32 wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
           int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
           void *cookie,
           void (*callback) (void *cookie, struct key_params *params));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static s32 wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
           u8 key_idx, bool pairwise, const u8 *mac_addr, struct key_params *params);
static s32 wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
           u8 key_idx, bool pairwise, const u8 *mac_addr);
static s32 wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
           u8 key_idx, bool pairwise, const u8 *mac_addr,
           void *cookie, void (*callback) (void *cookie, struct key_params *params));
#else
static s32 wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
           u8 key_idx, const u8 *mac_addr, struct key_params *params);
static s32 wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
           u8 key_idx, const u8 *mac_addr);
static s32 wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
           u8 key_idx, const u8 *mac_addr,
           void *cookie, void (*callback) (void *cookie, struct key_params *params));
#endif 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static s32 wl_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *dev,
           struct cfg80211_pmksa *pmksa);
static s32 wl_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *dev,
           struct cfg80211_pmksa *pmksa);
static s32 wl_cfg80211_flush_pmksa(struct wiphy *wiphy, struct net_device *dev);
#endif

static s32 wl_create_event_handler(struct wl_cfg80211_priv *wl);
static void wl_destroy_event_handler(struct wl_cfg80211_priv *wl);
static s32 wl_event_handler(void *data);
static void wl_init_eq(struct wl_cfg80211_priv *wl);
static void wl_flush_eq(struct wl_cfg80211_priv *wl);
static void wl_lock_eq(struct wl_cfg80211_priv *wl);
static void wl_unlock_eq(struct wl_cfg80211_priv *wl);
static void wl_init_eq_lock(struct wl_cfg80211_priv *wl);
static void wl_init_eloop_handler(struct wl_cfg80211_event_loop *el);
static struct wl_cfg80211_event_q *wl_deq_event(struct wl_cfg80211_priv *wl);
static s32 wl_enq_event(struct wl_cfg80211_priv *wl, u32 type,
	const wl_event_msg_t *msg, void *data);
static void wl_put_event(struct wl_cfg80211_event_q *e);
static void wl_wakeup_event(struct wl_cfg80211_priv *wl);

static s32 wl_notify_connect_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
           const wl_event_msg_t *e, void *data);
static s32 wl_notify_roaming_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
           const wl_event_msg_t *e, void *data);
static s32 wl_notify_scan_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
           const wl_event_msg_t *e, void *data);
static s32 wl_bss_connect_done(struct wl_cfg80211_priv *wl, struct net_device *ndev,
           const wl_event_msg_t *e, void *data, bool completed);
static s32 wl_bss_roaming_done(struct wl_cfg80211_priv *wl, struct net_device *ndev,
           const wl_event_msg_t *e, void *data);
static s32 wl_notify_mic_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
           const wl_event_msg_t *e, void *data);

static s32 wl_dev_bufvar_get(struct net_device *dev, s8 *name, s8 *buf, s32 buf_len);
static __used s32 wl_dev_bufvar_set(struct net_device *dev, s8 *name, s8 *buf, s32 len);
static s32 wl_dev_intvar_set(struct net_device *dev, s8 *name, s32 val);
static s32 wl_dev_intvar_get(struct net_device *dev, s8 *name, s32 *retval);
static s32 wl_dev_ioctl(struct net_device *dev, u32 cmd, void *arg, u32 len);

static s32 wl_set_frag(struct net_device *dev, u32 frag_threshold);
static s32 wl_set_rts(struct net_device *dev, u32 frag_threshold);
static s32 wl_set_retry(struct net_device *dev, u32 retry, bool l);

static void wl_init_prof(struct wl_cfg80211_profile *prof);

static s32 wl_set_wpa_version(struct net_device *dev, struct cfg80211_connect_params *sme);
static s32 wl_set_auth_type(struct net_device *dev, struct cfg80211_connect_params *sme);
static s32 wl_set_set_cipher(struct net_device *dev, struct cfg80211_connect_params *sme);
static s32 wl_set_key_mgmt(struct net_device *dev, struct cfg80211_connect_params *sme);
static s32 wl_set_set_sharedkey(struct net_device *dev, struct cfg80211_connect_params *sme);
static s32 wl_get_assoc_ies(struct wl_cfg80211_priv *wl);
static void wl_ch_to_chanspec(struct ieee80211_channel *chan,
            struct wl_join_params *join_params, size_t *join_params_size);

static void wl_rst_ie(struct wl_cfg80211_priv *wl);
static __used s32 wl_add_ie(struct wl_cfg80211_priv *wl, u8 t, u8 l, u8 *v);
static s32 wl_mrg_ie(struct wl_cfg80211_priv *wl, u8 *ie_stream, u16 ie_size);
static s32 wl_cp_ie(struct wl_cfg80211_priv *wl, u8 *dst, u16 dst_size);
static u32 wl_get_ielen(struct wl_cfg80211_priv *wl);

static s32 wl_mode_to_nl80211_iftype(s32 mode);

static s32 wl_alloc_wdev(struct device *dev, struct wireless_dev **rwdev);
static void wl_free_wdev(struct wl_cfg80211_priv *wl);

static s32 wl_inform_bss(struct wl_cfg80211_priv *wl, struct wl_scan_results *bss_list);
static s32 wl_inform_single_bss(struct wl_cfg80211_priv *wl, struct wl_bss_info *bi);
static s32 wl_update_bss_info(struct wl_cfg80211_priv *wl);

static void key_endian_to_device(struct wl_wsec_key *key);
static void key_endian_to_host(struct wl_wsec_key *key);

static s32 wl_init_priv_mem(struct wl_cfg80211_priv *wl);
static void wl_deinit_priv_mem(struct wl_cfg80211_priv *wl);

static bool wl_is_ibssmode(struct wl_cfg80211_priv *wl);

static void wl_link_up(struct wl_cfg80211_priv *wl);
static struct cfg80211_bss *wl_get_ess_bss(struct wl_cfg80211_priv *wl);
static void wl_link_down(struct wl_cfg80211_priv *wl);
static s32 wl_set_mode(struct net_device *ndev, s32 iftype);

static void wl_init_conf(struct wl_cfg80211_conf *conf);

static s32 wl_update_wiphybands(struct wl_cfg80211_priv *wl);

static __used s32 wl_update_pmklist(struct net_device *dev,
                  struct wl_cfg80211_pmk_list *pmk_list, s32 err);

#if defined(WL_DBGMSG_ENABLE)
#define WL_DBG_ESTR_MAX	32
static s8 wl_dbg_estr[][WL_DBG_ESTR_MAX] = {
	"SET_SSID", "JOIN", "START", "AUTH", "AUTH_IND",
	"DEAUTH", "DEAUTH_IND", "ASSOC", "ASSOC_IND", "REASSOC",
	"REASSOC_IND", "DISASSOC", "DISASSOC_IND", "QUIET_START", "QUIET_END",
	"BEACON_RX", "LINK", "MIC_ERROR", "NDIS_LINK", "ROAM",
	"TXFAIL", "PMKID_CACHE", "RETROGRADE_TSF", "PRUNE", "AUTOAUTH",
	"EAPOL_MSG", "SCAN_COMPLETE", "ADDTS_IND", "DELTS_IND", "BCNSENT_IND",
	"BCNRX_MSG", "BCNLOST_MSG", "ROAM_PREP", "PFN_NET_FOUND",
	"PFN_NET_LOST",
	"RESET_COMPLETE", "JOIN_START", "ROAM_START", "ASSOC_START",
	"IBSS_ASSOC",
	"RADIO", "PSM_WATCHDOG",
	"PROBREQ_MSG",
	"SCAN_CONFIRM_IND", "PSK_SUP", "COUNTRY_CODE_CHANGED",
	"EXCEEDED_MEDIUM_TIME", "ICV_ERROR",
	"UNICAST_DECODE_ERROR", "MULTICAST_DECODE_ERROR", "TRACE",
	"IF",
	"RSSI", "PFN_SCAN_COMPLETE", "ACTION_FRAME", "ACTION_FRAME_COMPLETE",
};
#endif				

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)
#define NL80211_BAND_2GHZ IEEE80211_BAND_2GHZ
#define NL80211_BAND_5GHZ IEEE80211_BAND_5GHZ
#endif

#define CHAN2G(_channel, _freq, _flags) {			\
	.band			= NL80211_BAND_2GHZ,		\
	.center_freq		= (_freq),			\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define CHAN5G(_channel, _flags) {				\
	.band			= NL80211_BAND_5GHZ,		\
	.center_freq		= 5000 + (5 * (_channel)),	\
	.hw_value		= (_channel),			\
	.flags			= (_flags),			\
	.max_antenna_gain	= 0,				\
	.max_power		= 30,				\
}

#define RATE_TO_BASE100KBPS(rate)   (((rate) * 10) / 2)
#define RATETAB_ENT(_rateid, _flags) \
	{                                                               \
		.bitrate        = RATE_TO_BASE100KBPS(_rateid),     \
		.hw_value       = (_rateid),                            \
		.flags          = (_flags),                             \
	}

static struct ieee80211_rate __wl_rates[] = {
	RATETAB_ENT(DOT11_RATE_1M, 0),
	RATETAB_ENT(DOT11_RATE_2M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(DOT11_RATE_5M5, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(DOT11_RATE_11M, IEEE80211_RATE_SHORT_PREAMBLE),
	RATETAB_ENT(DOT11_RATE_6M, 0),
	RATETAB_ENT(DOT11_RATE_9M, 0),
	RATETAB_ENT(DOT11_RATE_12M, 0),
	RATETAB_ENT(DOT11_RATE_18M, 0),
	RATETAB_ENT(DOT11_RATE_24M, 0),
	RATETAB_ENT(DOT11_RATE_36M, 0),
	RATETAB_ENT(DOT11_RATE_48M, 0),
	RATETAB_ENT(DOT11_RATE_54M, 0),
};

#define wl_a_rates		(__wl_rates + 4)
#define wl_a_rates_size	8
#define wl_g_rates		(__wl_rates + 0)
#define wl_g_rates_size	12

static struct ieee80211_channel __wl_2ghz_channels[] = {
	CHAN2G(1, 2412, 0),
	CHAN2G(2, 2417, 0),
	CHAN2G(3, 2422, 0),
	CHAN2G(4, 2427, 0),
	CHAN2G(5, 2432, 0),
	CHAN2G(6, 2437, 0),
	CHAN2G(7, 2442, 0),
	CHAN2G(8, 2447, 0),
	CHAN2G(9, 2452, 0),
	CHAN2G(10, 2457, 0),
	CHAN2G(11, 2462, 0),
	CHAN2G(12, 2467, 0),
	CHAN2G(13, 2472, 0),
	CHAN2G(14, 2484, 0),
};

static struct ieee80211_channel __wl_5ghz_a_channels[] = {
	CHAN5G(34, 0), CHAN5G(36, 0),
	CHAN5G(38, 0), CHAN5G(40, 0),
	CHAN5G(42, 0), CHAN5G(44, 0),
	CHAN5G(46, 0), CHAN5G(48, 0),
	CHAN5G(52, 0), CHAN5G(56, 0),
	CHAN5G(60, 0), CHAN5G(64, 0),
	CHAN5G(100, 0), CHAN5G(104, 0),
	CHAN5G(108, 0), CHAN5G(112, 0),
	CHAN5G(116, 0), CHAN5G(120, 0),
	CHAN5G(124, 0), CHAN5G(128, 0),
	CHAN5G(132, 0), CHAN5G(136, 0),
	CHAN5G(140, 0), CHAN5G(149, 0),
	CHAN5G(153, 0), CHAN5G(157, 0),
	CHAN5G(161, 0), CHAN5G(165, 0),
	CHAN5G(184, 0), CHAN5G(188, 0),
	CHAN5G(192, 0), CHAN5G(196, 0),
	CHAN5G(200, 0), CHAN5G(204, 0),
	CHAN5G(208, 0), CHAN5G(212, 0),
	CHAN5G(216, 0),
};

static struct ieee80211_channel __wl_5ghz_n_channels[] = {
	CHAN5G(32, 0), CHAN5G(34, 0),
	CHAN5G(36, 0), CHAN5G(38, 0),
	CHAN5G(40, 0), CHAN5G(42, 0),
	CHAN5G(44, 0), CHAN5G(46, 0),
	CHAN5G(48, 0), CHAN5G(50, 0),
	CHAN5G(52, 0), CHAN5G(54, 0),
	CHAN5G(56, 0), CHAN5G(58, 0),
	CHAN5G(60, 0), CHAN5G(62, 0),
	CHAN5G(64, 0), CHAN5G(66, 0),
	CHAN5G(68, 0), CHAN5G(70, 0),
	CHAN5G(72, 0), CHAN5G(74, 0),
	CHAN5G(76, 0), CHAN5G(78, 0),
	CHAN5G(80, 0), CHAN5G(82, 0),
	CHAN5G(84, 0), CHAN5G(86, 0),
	CHAN5G(88, 0), CHAN5G(90, 0),
	CHAN5G(92, 0), CHAN5G(94, 0),
	CHAN5G(96, 0), CHAN5G(98, 0),
	CHAN5G(100, 0), CHAN5G(102, 0),
	CHAN5G(104, 0), CHAN5G(106, 0),
	CHAN5G(108, 0), CHAN5G(110, 0),
	CHAN5G(112, 0), CHAN5G(114, 0),
	CHAN5G(116, 0), CHAN5G(118, 0),
	CHAN5G(120, 0), CHAN5G(122, 0),
	CHAN5G(124, 0), CHAN5G(126, 0),
	CHAN5G(128, 0), CHAN5G(130, 0),
	CHAN5G(132, 0), CHAN5G(134, 0),
	CHAN5G(136, 0), CHAN5G(138, 0),
	CHAN5G(140, 0), CHAN5G(142, 0),
	CHAN5G(144, 0), CHAN5G(145, 0),
	CHAN5G(146, 0), CHAN5G(147, 0),
	CHAN5G(148, 0), CHAN5G(149, 0),
	CHAN5G(150, 0), CHAN5G(151, 0),
	CHAN5G(152, 0), CHAN5G(153, 0),
	CHAN5G(154, 0), CHAN5G(155, 0),
	CHAN5G(156, 0), CHAN5G(157, 0),
	CHAN5G(158, 0), CHAN5G(159, 0),
	CHAN5G(160, 0), CHAN5G(161, 0),
	CHAN5G(162, 0), CHAN5G(163, 0),
	CHAN5G(164, 0), CHAN5G(165, 0),
	CHAN5G(166, 0), CHAN5G(168, 0),
	CHAN5G(170, 0), CHAN5G(172, 0),
	CHAN5G(174, 0), CHAN5G(176, 0),
	CHAN5G(178, 0), CHAN5G(180, 0),
	CHAN5G(182, 0), CHAN5G(184, 0),
	CHAN5G(186, 0), CHAN5G(188, 0),
	CHAN5G(190, 0), CHAN5G(192, 0),
	CHAN5G(194, 0), CHAN5G(196, 0),
	CHAN5G(198, 0), CHAN5G(200, 0),
	CHAN5G(202, 0), CHAN5G(204, 0),
	CHAN5G(206, 0), CHAN5G(208, 0),
	CHAN5G(210, 0), CHAN5G(212, 0),
	CHAN5G(214, 0), CHAN5G(216, 0),
	CHAN5G(218, 0), CHAN5G(220, 0),
	CHAN5G(222, 0), CHAN5G(224, 0),
	CHAN5G(226, 0), CHAN5G(228, 0),
};

static struct ieee80211_supported_band __wl_band_2ghz = {
	.band = NL80211_BAND_2GHZ,
	.channels = __wl_2ghz_channels,
	.n_channels = ARRAY_SIZE(__wl_2ghz_channels),
	.bitrates = wl_g_rates,
	.n_bitrates = wl_g_rates_size,
};

static struct ieee80211_supported_band __wl_band_5ghz_a = {
	.band = NL80211_BAND_5GHZ,
	.channels = __wl_5ghz_a_channels,
	.n_channels = ARRAY_SIZE(__wl_5ghz_a_channels),
	.bitrates = wl_a_rates,
	.n_bitrates = wl_a_rates_size,
};

static struct ieee80211_supported_band __wl_band_5ghz_n = {
	.band = NL80211_BAND_5GHZ,
	.channels = __wl_5ghz_n_channels,
	.n_channels = ARRAY_SIZE(__wl_5ghz_n_channels),
	.bitrates = wl_a_rates,
	.n_bitrates = wl_a_rates_size,
};

static const u32 __wl_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_AES_CMAC,
};

static void key_endian_to_device(struct wl_wsec_key *key)
{
	key->index = htod32(key->index);
	key->len = htod32(key->len);
	key->algo = htod32(key->algo);
	key->flags = htod32(key->flags);
	key->rxiv.hi = htod32(key->rxiv.hi);
	key->rxiv.lo = htod16(key->rxiv.lo);
	key->iv_initialized = htod32(key->iv_initialized);
}

static void key_endian_to_host(struct wl_wsec_key *key)
{
	key->index = dtoh32(key->index);
	key->len = dtoh32(key->len);
	key->algo = dtoh32(key->algo);
	key->flags = dtoh32(key->flags);
	key->rxiv.hi = dtoh32(key->rxiv.hi);
	key->rxiv.lo = dtoh16(key->rxiv.lo);
	key->iv_initialized = dtoh32(key->iv_initialized);
}

static s32
wl_dev_ioctl(struct net_device *dev, u32 cmd, void *arg, u32 len)
{
	BUG_ON(len < sizeof(int));
	return wlc_ioctl_internal(dev, cmd, arg, len);
}

static s32
wl_cfg80211_change_iface(struct wiphy *wiphy, struct net_device *ndev,
                         enum nl80211_iftype type,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
                         u32 *flags,
#endif
                         struct vif_params *params)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct wireless_dev *wdev;
	s32 infra = 0;
	s32 ap = 0;
	s32 err = 0;

	switch (type) {
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_WDS:
		WL_ERR(("type (%d) : currently we do not support this type\n",
			type));
		return -EOPNOTSUPP;
	case NL80211_IFTYPE_ADHOC:
		wl->conf->mode = WL_MODE_IBSS;
		break;
	case NL80211_IFTYPE_STATION:
		wl->conf->mode = WL_MODE_BSS;
		infra = 1;
		break;
	default:
		return -EINVAL;
	}
	infra = htod32(infra);
	ap = htod32(ap);
	wdev = ndev->ieee80211_ptr;
	wdev->iftype = type;
	WL_DBG(("%s : ap (%d), infra (%d)\n", ndev->name, ap, infra));
	err = wl_dev_ioctl(ndev, WLC_SET_INFRA, &infra, sizeof(infra));
	if (err) {
		WL_ERR(("WLC_SET_INFRA error (%d)\n", err));
		return err;
	}
	err = wl_dev_ioctl(ndev, WLC_SET_AP, &ap, sizeof(ap));
	if (err) {
		WL_ERR(("WLC_SET_AP error (%d)\n", err));
		return err;
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
static s32
wl_cfg80211_scan(struct wiphy *wiphy,
                 struct cfg80211_scan_request *request)
#else
static s32
wl_cfg80211_scan(struct wiphy *wiphy,
                 struct net_device *ndev,
                 struct cfg80211_scan_request *request)
#endif

{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	struct net_device *ndev = request->wdev->netdev;
#endif
	struct wl_cfg80211_priv *wl = ndev_to_wl(ndev);
	struct cfg80211_ssid *ssids;
	struct wl_cfg80211_scan_req *sr = wl_to_sr(wl);
	s32 passive_scan;
	s32 err = 0;

	if (request) {		
		ssids = request->ssids;
	}
	else {		

		ssids = NULL;
	}
	wl->scan_request = request;

	memset(&sr->ssid, 0, sizeof(sr->ssid));

	if (ssids) {
		WL_DBG(("ssid \"%s\", ssid_len (%d)\n", ssids->ssid, ssids->ssid_len));
		sr->ssid.SSID_len = min_t(u8, sizeof(sr->ssid.SSID), ssids->ssid_len);
	}

	if (sr->ssid.SSID_len) {
		memcpy(sr->ssid.SSID, ssids->ssid, sr->ssid.SSID_len);
		sr->ssid.SSID_len = htod32(sr->ssid.SSID_len);
		WL_DBG(("Specific scan ssid=\"%s\" len=%d\n", sr->ssid.SSID, sr->ssid.SSID_len));
	} else {
		WL_DBG(("Broadcast scan\n"));
	}
	WL_DBG(("sr->ssid.SSID_len (%d)\n", sr->ssid.SSID_len));
	passive_scan = wl->active_scan ? 0 : 1;
	err = wl_dev_ioctl(ndev, WLC_SET_PASSIVE_SCAN, &passive_scan, sizeof(passive_scan));
	if (err) {
		WL_ERR(("WLC_SET_PASSIVE_SCAN error (%d)\n", err));
		goto scan_out;
	}
	err = wl_dev_ioctl(ndev, WLC_SCAN, &sr->ssid, sizeof(sr->ssid));
	if (err) {
		if (err == -EBUSY) {
			WL_INF(("system busy : scan for \"%s\" "
				"canceled\n", sr->ssid.SSID));
		} else {
			WL_ERR(("WLC_SCAN error (%d)\n", err));
		}
		goto scan_out;
	}

	return 0;

scan_out:
	wl->scan_request = NULL;
	return err;
}

static s32 wl_dev_intvar_set(struct net_device *dev, s8 *name, s32 val)
{
	s8 buf[WLC_IOCTL_SMLEN];
	u32 len;
	s32 err = 0;

	val = htod32(val);
	len = bcm_mkiovar(name, (char *)(&val), sizeof(val), buf, sizeof(buf));
	BUG_ON(!len);

	err = wl_dev_ioctl(dev, WLC_SET_VAR, buf, len);
	if (err) {
		WL_ERR(("error (%d)\n", err));
	}

	return err;
}

static s32
wl_dev_intvar_get(struct net_device *dev, s8 *name, s32 *retval)
{
	union {
		s8 buf[WLC_IOCTL_SMLEN];
		s32 val;
	} var;
	u32 len;
	u32 data_null;
	s32 err = 0;

	len = bcm_mkiovar(name, (char *)(&data_null), 0, (char *)(&var), sizeof(var.buf));
	BUG_ON(!len);
	err = wl_dev_ioctl(dev, WLC_GET_VAR, &var, len);
	if (err) {
		WL_ERR(("error (%d)\n", err));
	}
	*retval = dtoh32(var.val);

	return err;
}

static s32 wl_set_rts(struct net_device *dev, u32 rts_threshold)
{
	s32 err = 0;

	err = wl_dev_intvar_set(dev, "rtsthresh", rts_threshold);
	if (err) {
		WL_ERR(("Error (%d)\n", err));
		return err;
	}
	return err;
}

static s32 wl_set_frag(struct net_device *dev, u32 frag_threshold)
{
	s32 err = 0;

	err = wl_dev_intvar_set(dev, "fragthresh", frag_threshold);
	if (err) {
		WL_ERR(("Error (%d)\n", err));
		return err;
	}
	return err;
}

static s32 wl_set_retry(struct net_device *dev, u32 retry, bool l)
{
	s32 err = 0;
	u32 cmd = (l ? WLC_SET_LRL : WLC_SET_SRL);

	retry = htod32(retry);
	err = wl_dev_ioctl(dev, cmd, &retry, sizeof(retry));
	if (err) {
		WL_ERR(("cmd (%d) , error (%d)\n", cmd, err));
		return err;
	}
	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, int radio_idx, u32 changed)
#else
static s32 wl_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed)
#endif
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct net_device *ndev = wl_to_ndev(wl);
	s32 err = 0;

	if (changed & WIPHY_PARAM_RTS_THRESHOLD &&
	    (wl->conf->rts_threshold != wiphy->rts_threshold)) {
		wl->conf->rts_threshold = wiphy->rts_threshold;
		err = wl_set_rts(ndev, wl->conf->rts_threshold);
		if (!err)
			return err;
	}
	if (changed & WIPHY_PARAM_FRAG_THRESHOLD &&
	    (wl->conf->frag_threshold != wiphy->frag_threshold)) {
		wl->conf->frag_threshold = wiphy->frag_threshold;
		err = wl_set_frag(ndev, wl->conf->frag_threshold);
		if (!err)
			return err;
	}
	if (changed & WIPHY_PARAM_RETRY_LONG && (wl->conf->retry_long != wiphy->retry_long)) {
		wl->conf->retry_long = wiphy->retry_long;
		err = wl_set_retry(ndev, wl->conf->retry_long, true);
		if (!err)
			return err;
	}
	if (changed & WIPHY_PARAM_RETRY_SHORT && (wl->conf->retry_short != wiphy->retry_short)) {
		wl->conf->retry_short = wiphy->retry_short;
		err = wl_set_retry(ndev, wl->conf->retry_short, false);
		if (!err) {
			return err;
		}
	}

	return err;
}

static s32
wl_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *dev,
                      struct cfg80211_ibss_params *params)
{
	struct wl_join_params join_params;
	size_t join_params_size;
	s32 val;
	s32 err = 0;

	WL_DBG(("\n"));

	if (params->bssid) {
		WL_ERR(("Invalid bssid\n"));
		return -EOPNOTSUPP;
	}

	if ((err = wl_dev_intvar_set(dev, "auth", 0))) {
		return err;
	}
	if ((err = wl_dev_intvar_set(dev, "wpa_auth", WPA_AUTH_NONE))) {
		return err;
	}
	if ((err = wl_dev_intvar_get(dev, "wsec", &val))) {
		return err;
	}
	val &= ~(WEP_ENABLED | TKIP_ENABLED | AES_ENABLED);
	if ((err = wl_dev_intvar_set(dev, "wsec", val))) {
		return err;
	}

	memset(&join_params, 0, sizeof(join_params));
	join_params_size = sizeof(join_params.ssid);

	memcpy((void *)join_params.ssid.SSID, (void *)params->ssid, params->ssid_len);
	join_params.ssid.SSID_len = htod32(params->ssid_len);
	if (params->bssid)
		memcpy(&join_params.params.bssid, params->bssid, ETHER_ADDR_LEN);
	else
		memset(&join_params.params.bssid, 0, ETHER_ADDR_LEN);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	wl_ch_to_chanspec(params->chandef.chan, &join_params, &join_params_size);
#else
	wl_ch_to_chanspec(params->channel, &join_params, &join_params_size);
#endif
	err = wl_dev_ioctl(dev, WLC_SET_SSID, &join_params, join_params_size);
	if (err) {
		WL_ERR(("Error (%d)\n", err));
		return err;
	}
	return err;
}

static s32 wl_cfg80211_leave_ibss(struct wiphy *wiphy, struct net_device *dev)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	s32 err = 0;

	WL_DBG(("\n"));

	wl_link_down(wl);

	return err;
}

extern int re_verbose;   /* verbose debug toggle (module param, defined in wl_linux.c) */
extern void wl_re_release_assoc_ie(void);
#define re_log(...) do { if (re_verbose) printk(KERN_ERR __VA_ARGS__); } while (0)

/* Scan an IE blob for the RSN element and report whether it lists the SAE AKM (00-0F-AC:8).
 * Returns 1 = RSN IE present and offers SAE, 0 = RSN IE present without SAE, -1 = no RSN IE. */
static int wl_rsn_ie_has_sae(const u8 *ie, size_t len)
{
	while (ie && len >= 2) {
		size_t elen = ie[1];
		if (elen + 2 > len)
			break;
		if (ie[0] == WLAN_EID_RSN) {
			const u8 *p = ie + 2;
			size_t rem = elen;
			u16 n, i;
			/* version(2) group(4) pairwise-count(2) pairwise(4*n) akm-count(2) akm(4*m) */
			if (rem < 8)
				return 0;
			n = p[6] | (p[7] << 8);
			if (rem < 8 + (size_t)n * 4 + 2)
				return 0;
			p += 8 + n * 4;
			rem -= 8 + n * 4;
			n = p[0] | (p[1] << 8);
			p += 2;
			rem -= 2;
			for (i = 0; i < n && rem >= 4; i++, p += 4, rem -= 4)
				if (p[0] == 0x00 && p[1] == 0x0f && p[2] == 0xac && p[3] == 8)
					return 1;
			return 0;
		}
		ie += elen + 2;
		len -= elen + 2;
	}
	return -1;
}

/* Does the RSN element in this IE blob demand protected management frames (RSN capabilities, MFPR)?
 * wpa_supplicant sets MFPR only for "PMF required"; for "optional" it sets MFPC alone, but then
 * still passes NL80211_MFP_REQUIRED to the kernel when the AP is PMF-capable, so cfg80211's mfp
 * flag cannot tell the two apart. */
static bool wl_rsn_ie_mfpr(const u8 *ie, size_t len)
{
	while (ie && len >= 2) {
		size_t elen = ie[1];
		if (elen + 2 > len)
			break;
		if (ie[0] == WLAN_EID_RSN) {
			const u8 *p = ie + 2;
			size_t rem = elen;
			u16 n;
			/* version(2) group(4) pairwise-count(2) pairwise(4*n) akm-count(2) akm(4*m) caps(2) */
			if (rem < 8)
				return false;
			n = p[6] | (p[7] << 8);
			if (rem < 8 + (size_t)n * 4 + 2)
				return false;
			p += 8 + n * 4;
			rem -= 8 + n * 4;
			n = p[0] | (p[1] << 8);
			p += 2;
			rem -= 2;
			if (rem < (size_t)n * 4 + 2)
				return false;
			p += n * 4;
			return (p[0] | (p[1] << 8)) & 0x0040;
		}
		ie += elen + 2;
		len -= elen + 2;
	}
	return false;
}

/* Does this connect request ask for WPA3-SAE? Checked by auth_type, every offered AKM and the
 * RSN IE wpa_supplicant built -- not just akm_suites[0]. */
static bool wl_sme_is_sae(struct cfg80211_connect_params *sme)
{
	int i;
	if (sme->auth_type == NL80211_AUTHTYPE_SAE)
		return true;
	for (i = 0; i < sme->crypto.n_akm_suites; i++)
		if (sme->crypto.akm_suites[i] == WLAN_AKM_SUITE_SAE)
			return true;
	return wl_rsn_ie_has_sae(sme->ie, sme->ie_len) == 1;
}

static s32
wl_set_wpa_version(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	s32 val = 0;
	s32 err = 0;

	if (sme->crypto.wpa_versions & NL80211_WPA_VERSION_1)
		val = WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED;
	else if (sme->crypto.wpa_versions & (NL80211_WPA_VERSION_2 | BIT(2) /* NL80211_WPA_VERSION_3: SAE */))
		val = WPA2_AUTH_PSK | WPA2_AUTH_UNSPECIFIED;
	else
		val = WPA_AUTH_DISABLED;
	WL_DBG(("setting wpa_auth to 0x%0x\n", val));
	err = wl_dev_intvar_set(dev, "wpa_auth", val);
	if (err) {
		WL_ERR(("set wpa_auth failed (%d)\n", err));
		return err;
	}
	wl->profile->sec.wpa_versions = sme->crypto.wpa_versions;
	return err;
}

static s32
wl_set_auth_type(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	s32 val = 0;
	s32 err = 0;

	re_log("re: auth_type=%d n_akm=%d akm0=0x%x n_ciph=%d\n", sme->auth_type,
	       sme->crypto.n_akm_suites,
	       sme->crypto.n_akm_suites ? sme->crypto.akm_suites[0] : 0,
	       sme->crypto.n_ciphers_pairwise);

	switch (sme->auth_type) {
	case NL80211_AUTHTYPE_OPEN_SYSTEM:
		val = 0;
		WL_DBG(("open system\n"));
		break;
	case NL80211_AUTHTYPE_SHARED_KEY:
		val = 1;
		WL_DBG(("shared key\n"));
		break;
	case NL80211_AUTHTYPE_AUTOMATIC:
		val = 2;
		WL_DBG(("automatic\n"));
		break;
	case NL80211_AUTHTYPE_SAE:
		val = 3; /* WPA3-SAE: DOT11_SAE auth alg. Requires blob patch P1 (auth-clamp passthrough). */
		WL_DBG(("SAE\n"));
		break;
	case NL80211_AUTHTYPE_NETWORK_EAP:
		WL_DBG(("network eap\n"));
#ifdef fallthrough
		fallthrough;
#endif
	default:
		val = 2;
		WL_ERR(("invalid auth type (%d)\n", sme->auth_type));
		break;
	}

	/* WPA3-SAE detection by AKM, not auth_type: NetworkManager/wpa_supplicant offloads SAE
	 * to userspace and sends the CONNECT with auth_type=OPEN, so keying on auth_type misses it.
	 * Force the SAE auth alg (3) whenever the AKM is SAE so the firmware enters the SAE auth
	 * state and __wrap_wlc_sendauth captures the scb/BSSID. */
	if (wl_sme_is_sae(sme)) {
		val = 3;
		re_log("re: forcing auth alg=3 (SAE AKM, connect auth_type=%d)\n", sme->auth_type);
	}

	err = wl_dev_intvar_set(dev, "auth", val);
	if (err) {
		WL_ERR(("set auth failed (%d)\n", err));
		return err;
	}

	wl->profile->sec.auth_type = sme->auth_type;
	return err;
}

static s32
wl_set_set_cipher(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	s32 pval = 0;
	s32 gval = 0;
	s32 val = 0;
	s32 err = 0;

	if (sme->crypto.n_ciphers_pairwise) {
		switch (sme->crypto.ciphers_pairwise[0]) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			pval = WEP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			pval = TKIP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			pval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			pval = AES_ENABLED;
			break;
		default:
			WL_ERR(("invalid cipher pairwise (%d)\n", sme->crypto.ciphers_pairwise[0]));
			return -EINVAL;
		}
	}
	if (sme->crypto.cipher_group) {
		switch (sme->crypto.cipher_group) {
		case WLAN_CIPHER_SUITE_WEP40:
		case WLAN_CIPHER_SUITE_WEP104:
			gval = WEP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_TKIP:
			gval = TKIP_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_CCMP:
			gval = AES_ENABLED;
			break;
		case WLAN_CIPHER_SUITE_AES_CMAC:
			gval = AES_ENABLED;
			break;
		default:
			WL_ERR(("invalid cipher group (%d)\n", sme->crypto.cipher_group));
			return -EINVAL;
		}
	}

	if ((err = wl_dev_intvar_get(dev, "wsec", &val))) {
		return err;
	}
	val &= ~(WEP_ENABLED | TKIP_ENABLED | AES_ENABLED);
	val |= pval | gval;
	WL_DBG(("set wsec to %d\n", val));
	err = wl_dev_intvar_set(dev, "wsec", val);
	if (err) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}

	wl->profile->sec.cipher_pairwise = sme->crypto.ciphers_pairwise[0];
	wl->profile->sec.cipher_group = sme->crypto.cipher_group;

	return err;
}

static s32
wl_set_key_mgmt(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	s32 val = 0;
	s32 err = 0;

	if (sme->crypto.n_akm_suites) {
		err = wl_dev_intvar_get(dev, "wpa_auth", &val);
		if (err) {
			WL_ERR(("could not get wpa_auth (%d)\n", err));
			return err;
		}
		if (val & (WPA_AUTH_PSK | WPA_AUTH_UNSPECIFIED)) {
			switch (sme->crypto.akm_suites[0]) {
			case WLAN_AKM_SUITE_8021X:
				val = WPA_AUTH_UNSPECIFIED;
				break;
			case WLAN_AKM_SUITE_PSK:
				val = WPA_AUTH_PSK;
				break;
			default:
				WL_ERR(("invalid cipher group (%d)\n", sme->crypto.cipher_group));
				return -EINVAL;
			}
		} else if (val & (WPA2_AUTH_PSK | WPA2_AUTH_UNSPECIFIED)) {
			switch (sme->crypto.akm_suites[0]) {
			case WLAN_AKM_SUITE_8021X:
				val = WPA2_AUTH_UNSPECIFIED;
				break;
			case WLAN_AKM_SUITE_PSK:
				val = WPA2_AUTH_PSK;
				break;
			case WLAN_AKM_SUITE_SAE:
				/* M2a: route SAE AKM through the PSK wpa_auth path so the
				 * connect proceeds and the firmware emits an alg=3 auth frame.
				 * A dedicated SAE wpa_auth bit + RSN-IE/AKM-gate work lands in M3. */
				val = WPA2_AUTH_PSK;
				break;
			default:
				WL_ERR(("invalid cipher group (%d)\n", sme->crypto.cipher_group));
				return -EINVAL;
			}
		}

		WL_DBG(("setting wpa_auth to %d\n", val));
		err = wl_dev_intvar_set(dev, "wpa_auth", val);
		if (err) {
			WL_ERR(("could not set wpa_auth (%d)\n", err));
			return err;
		}
	}

	wl->profile->sec.wpa_auth = sme->crypto.akm_suites[0];

	return err;
}

static s32
wl_set_set_sharedkey(struct net_device *dev, struct cfg80211_connect_params *sme)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	struct wl_cfg80211_security *sec;
	struct wl_wsec_key key;
	s32 err = 0;

	WL_DBG(("key len (%d)\n", sme->key_len));
	if (sme->key_len) {
		sec = &wl->profile->sec;
		WL_DBG(("wpa_versions 0x%x cipher_pairwise 0x%x\n",
		         sec->wpa_versions, sec->cipher_pairwise));
		if (!(sec->wpa_versions & (NL80211_WPA_VERSION_1 | NL80211_WPA_VERSION_2)) &&
		     (sec->cipher_pairwise &
		     (WLAN_CIPHER_SUITE_WEP40 | WLAN_CIPHER_SUITE_WEP104))) {
			memset(&key, 0, sizeof(key));
			key.len = (u32) sme->key_len;
			key.index = (u32) sme->key_idx;
			if (key.len > sizeof(key.data)) {
				WL_ERR(("Too long key length (%u)\n", key.len));
				return -EINVAL;
			}
			memcpy(key.data, sme->key, key.len);
			key.flags = WL_PRIMARY_KEY;
			switch (sec->cipher_pairwise) {
			case WLAN_CIPHER_SUITE_WEP40:
				key.algo = CRYPTO_ALGO_WEP1;
				break;
			case WLAN_CIPHER_SUITE_WEP104:
				key.algo = CRYPTO_ALGO_WEP128;
				break;
			default:
				WL_ERR(("Invalid algorithm (%d)\n",
				        sme->crypto.ciphers_pairwise[0]));
				return -EINVAL;
			}

			WL_DBG(("key length (%d) key index (%d) algo (%d)\n", key.len,
				key.index, key.algo));
			WL_DBG(("key \"%s\"\n", key.data));
			key_endian_to_device(&key);
			err = wl_dev_ioctl(dev, WLC_SET_KEY, &key, sizeof(key));
			if (err) {
				WL_ERR(("WLC_SET_KEY error (%d)\n", err));
				return err;
			}
		}
	}
	return err;
}

/* cfg80211_external_auth_request() needs wdev->u.client.ssid_len, which cfg80211
 * only sets AFTER .connect returns -- so kick external-auth START from a deferred
 * work item instead of inline in .connect. */
static struct {
	struct net_device *dev;
	u8 bssid[ETH_ALEN];
	struct cfg80211_ssid ssid;
	struct delayed_work work;
	bool inited;
	void *bsscfg;       /* captured from the firmware's wlc_sendauth call (M3.3 assoc drive) */
	void *scb;          /* AP scb, captured from wlc_sendauth arg4 (for host mgmt TX queue) */
	u8  assoc_ie[300];  /* wpa_supplicant's assoc IEs (RSN+RSNXE) captured at .connect; the
	                     * firmware emits this verbatim in the assoc-req so it matches the AP's
	                     * SAE+MFP requirement and the userspace 4-way RSN-IE check. */
	u16 assoc_ie_len;
	bool pmf_active;    /* 802.11w MFP negotiated + IGTK installed -> enforce SW PMF on RX */
	u8  igtk[16];       /* IGTK (BIP-CMAC-128 key) captured from .add_key for MMIE verify */
	u8  igtk_keyid;     /* IGTK key id (4 or 5) */
	u8  igtk_ipn[6];    /* IGTK packet number (replay) */
	u8  tk[16];         /* pairwise CCMP temporal key (PTK TK) for SW mgmt-frame crypto */
	bool tk_set;
	atomic64_t tx_pn;   /* our TX PN for SW-protected mgmt frames (SA-Query Response, Block Ack) */
	u64 rx_ba_pn;       /* last accepted PN of the AP's protected Block-Ack action frames */
	struct delayed_work assoc_wd;  /* association watchdog: see wl_sae_assoc_wd_work() */
	struct work_struct saq_work;   /* deferred SA-Query handler (RX path is atomic) */
	u8  saq_frame[320];
	unsigned int saq_len;
	bool saq_busy;
	/* AP teardown detection (802.11w SA Query + protected deauth/disassoc). */
	struct work_struct dd_work;    /* process a captured deauth/disassoc, or a liveness probe */
	struct delayed_work saq_chk;   /* SA-Query retry / timeout */
	u8  dd_frame[96];
	unsigned int dd_len;
	bool dd_busy, dd_prot;
	int  dd_kind;                  /* 0 = captured frame, 1 = liveness probe (after resume) */
	bool saq_pending;
	u16  saq_tid;
	int  saq_tries;
	u64  rx_mgmt_pn;               /* last accepted PN of the AP's protected deauth/disassoc */
	bool stub_seen;     /* the blob has sent its own stub auth frame for this join */
	atomic_t txfail_cnt;           /* WLC_E_TXFAIL events seen (a frame the AP never ACKed) */
	u32  assoc_status;             /* 802.11 status code of the last association response (WLC_E_ASSOC) */
	struct delayed_work retry_work; /* retry a join the AP answered with status 30 */
	struct delayed_work join_work; /* issue a join deferred by the rejoin quiet time */
	struct delayed_work hs_wd;     /* 4-way handshake watchdog */
	u8   join_buf[128];            /* the WLC_SET_SSID request of the current connect, for retries */
	size_t join_len;
	int  retries;                  /* internal join retries used for this connect */
	bool ptk_done;                 /* pairwise key installed = 4-way handshake completed */
	unsigned long last_disc;       /* jiffies of the last disconnect */
	bool sae_conn;      /* current connect request is WPA3-SAE (set in .connect) */
	bool sae_ok;        /* host SAE finished OK (.external_auth status 0) for this connection */
	u32  freq;          /* MHz of the connect channel (0 = unknown) */
	int armed;          /* SAFETY GATE: hooks do SAE work ONLY while armed (set at connect,
	                     * cleared after SAE/assoc + on disconnect). Keeps the RX tasklet hook
	                     * inert outside the brief active-SAE window. */
} wl_sae;

static void wl_re_saq_work(struct work_struct *w);   /* SW SA-Query responder (defined below) */
static int wl_re_send_protected_deauth(struct net_device *dev, u16 reason);   /* defined below */
static void wl_re_dd_work(struct work_struct *w);
static void wl_re_assoc_lost(struct net_device *dev, u16 reason, const char *why);
static void wl_re_saq_chk_work(struct work_struct *w);
void wl_re_link_tick(struct net_device *dev, unsigned long tx, unsigned long retry);
static void wl_re_fast_key(const u8 *tk);
static void wl_re_crypto_exit(void);

/* After the host SAE succeeds we drive the blob into association (wl_re_drive_assoc). With this
 * blob the association request sometimes never completes (seen with the original code too, ~50%
 * of connects on a FRITZ!Box 6690), and wpa_supplicant then only notices after its own 10 s
 * timeout. Fail the connect ourselves after a short grace period so it retries right away.
 * A normal association completes within ~50 ms of re_auth_advance. */
/* The blob sends a stub SAE auth frame of its own for every join (needed so it enters the
 * authenticating state; the AP rejects it). The real exchange, driven by wpa_supplicant, MUST start
 * after that stub: if our SAE commit goes out first, the late stub makes the AP discard its SAE
 * state and the join collapses ~0.3 s later (SET_SSID FAIL). The stub's timing varies (100-340 ms
 * after the join; later when the AP's scb already exists, i.e. when re-joining the same BSS), so a
 * fixed delay cannot work: start when the stub has been sent, with a fallback if it never is. */
#define WL_SAE_STUB_GRACE_MS		40
#define WL_SAE_START_FALLBACK_MS	500
#define WL_SAE_ASSOC_TIMEOUT_MS	3000

/* Tunables (ms). A full reconnect should neither be needlessly fast nor ever slow: these keep every
 * step bounded. */
#define WL_DEAUTH_SETTLE_MS	40	/* after our protected deauth, to see whether it was ACKed */
#define WL_MIN_REJOIN_GAP_MS	2000	/* quiet time after a disconnect before the next join */
#define WL_SAE_RETRY_DELAY_MS	1000	/* before retrying a failed join */
#define WL_SAE_MAX_RETRIES	3
#define WL_HS_TIMEOUT_MS	3500	/* association accepted but no 4-way handshake after this long */

/* A join the firmware reports as failed (WLC_E_SET_SSID / FAIL, as opposed to "no network found").
 * Seen when re-joining the BSS we just left, with WPA2-PSK as well as with SAE: the AP either answers
 * the association request with status 30 ("rejected temporarily, try again later") or does not answer
 * the authentication at all for a moment.
 * Reporting the failure sends wpa_supplicant on a ~3.5 s scan, a hop to the other band and, in 2 of 5
 * cases, a 10 s wait for a 4-way handshake that never starts. Wait a moment and join the same BSS
 * again, silently (bounded: WL_SAE_MAX_RETRIES times, then the failure is reported as before). */

/* Send the saved WLC_SET_SSID request (wl_sae.join_buf). For SAE this also arms the host exchange,
 * which is started once the blob's stub auth frame is out (or after a fallback delay). */
static int wl_sae_issue_join(struct net_device *dev)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	int err;

	if (wl_sae.sae_conn) {   /* SAE: a fresh host-driven exchange; other joins are fully blob-driven */
		wl_sae.stub_seen = false;
		wl_sae.armed = 1;
		schedule_delayed_work(&wl_sae.work, msecs_to_jiffies(WL_SAE_START_FALLBACK_MS));
	}
	err = wl_dev_ioctl(dev, WLC_SET_SSID, wl_sae.join_buf, wl_sae.join_len);
	if (err) {
		if (wl_sae.sae_conn) {
			wl_sae.armed = 0;
			cancel_delayed_work(&wl_sae.work);
		}
		return err;
	}
	set_bit(WL_STATUS_CONNECTING, &wl->status);
	re_log("re: CONNECTING set\n");
	return 0;
}

/* .connect must not sleep (it runs under the wiphy mutex / RTNL, which would stall every other
 * wireless operation), so a join that has to wait out the rejoin quiet time is issued from here. */
static void wl_sae_join_work(struct work_struct *w)
{
	struct net_device *dev = wl_sae.dev;
	int err;

	if (!dev || !wl_sae.join_len)
		return;
	err = wl_sae_issue_join(dev);
	if (err) {
		WL_ERR(("deferred join failed (%d)\n", err));
		cfg80211_connect_result(dev, wl_sae.bssid, NULL, 0, NULL, 0,
		                        WLAN_STATUS_AUTH_TIMEOUT, GFP_KERNEL);
	}
}

static void wl_sae_retry_work(struct work_struct *w)
{
	struct net_device *dev = wl_sae.dev;
	struct wl_cfg80211_priv *wl;
	int err;

	if (!dev || !wl_sae.join_len)
		return;
	wl = ndev_to_wl(dev);
	if (!test_bit(WL_STATUS_CONNECTING, &wl->status))
		return;
	wl_sae.retries++;
	wl_sae.assoc_status = 0;
	re_log("re: retrying the join (#%d) after the AP's 'try again later'\n", wl_sae.retries);
	if (wl_sae.sae_conn) {
		wl_sae.sae_ok = false;
		wl_re_release_assoc_ie();
	}
	err = wl_sae_issue_join(dev);
	if (err) {
		re_log("re: join retry failed (%d) -> reporting the failure\n", err);
		if (test_and_clear_bit(WL_STATUS_CONNECTING, &wl->status))
			cfg80211_connect_result(dev, wl_sae.bssid, NULL, 0, NULL, 0,
			                        WLAN_STATUS_AUTH_TIMEOUT, GFP_KERNEL);
	}
}

/* The association was accepted but the AP never starts the 4-way handshake (seen right after a
 * rejected join); wpa_supplicant would wait its full 10 s. Give it a bounded time, then drop the link
 * so it retries at once. */
static void wl_sae_hs_wd_work(struct work_struct *w)
{
	struct net_device *dev = wl_sae.dev;

	if (!dev || wl_sae.ptk_done)
		return;
	wl_re_assoc_lost(dev, WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT, "no 4-way handshake after association");
}
static void wl_sae_assoc_wd_work(struct work_struct *w)
{
	struct net_device *dev = wl_sae.dev;
	struct wl_cfg80211_priv *wl;
	scb_val_t scbval;

	if (!dev)
		return;
	wl = ndev_to_wl(dev);
	re_log("re: assoc watchdog fired: connecting=%d connected=%d\n",
	       test_bit(WL_STATUS_CONNECTING, &wl->status), test_bit(WL_STATUS_CONNECTED, &wl->status));
	/* wl_bss_connect_done() clears CONNECTING on link-up; whoever clears it first reports. */
	if (!test_and_clear_bit(WL_STATUS_CONNECTING, &wl->status))
		return;
	re_log("re: association did not complete within %d ms -> failing connect\n",
	       WL_SAE_ASSOC_TIMEOUT_MS);
	memset(&scbval, 0, sizeof(scbval));
	memcpy(&scbval.ea, wl_sae.bssid, ETHER_ADDR_LEN);
	scbval.val = htod32(WLAN_REASON_UNSPECIFIED);
	wl_dev_ioctl(dev, WLC_DISASSOC, &scbval, sizeof(scbval));
	wl_sae.sae_ok = false;
	cfg80211_connect_result(dev, wl_sae.bssid, NULL, 0, NULL, 0,
	                        WLAN_STATUS_AUTH_TIMEOUT, GFP_KERNEL);
}

static void wl_sae_ext_auth_work(struct work_struct *w)
{
	struct cfg80211_external_auth_params ext;
	int rc;
	if (!wl_sae.dev)
		return;
	memset(&ext, 0, sizeof(ext));
	ext.action = NL80211_EXTERNAL_AUTH_START;
	ext.key_mgmt_suite = WLAN_AKM_SUITE_SAE;
	memcpy(ext.bssid, wl_sae.bssid, ETH_ALEN);
	ext.ssid = wl_sae.ssid;
	rc = cfg80211_external_auth_request(wl_sae.dev, &ext, GFP_KERNEL);
	re_log("re: deferred external SAE auth for %pM -> %d\n", wl_sae.bssid, rc);
}

static s32
wl_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
                    struct cfg80211_connect_params *sme)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct wl_join_params join_params;
	size_t join_params_size;
	char valc;
	s32 err = 0;

	if (!sme->ssid) {
		WL_ERR(("Invalid ssid\n"));
		return -EOPNOTSUPP;
	}

	/* The blob can only do 802.11w together with SAE (we supply the RSN element and the PMF handling
	 * for that). A WPA2-PSK join is built by the blob alone, with an RSN element that has no PMF bits,
	 * so "PMF required" (MFPR in the RSN element) would silently connect without PMF. Fail closed
	 * instead. "Optional" (MFPC only) is fine: it means "if possible". */
	re_log("re: connect request: mfp=%d sae=%d rsn_mfpr=%d ie_len=%zu akms=%d wpa_versions=0x%x\n",
	       sme->mfp, wl_sme_is_sae(sme), wl_rsn_ie_mfpr(sme->ie, sme->ie_len), sme->ie_len,
	       sme->crypto.n_akm_suites, sme->crypto.wpa_versions);
	if (!wl_sme_is_sae(sme) && wl_rsn_ie_mfpr(sme->ie, sme->ie_len)) {
		pr_warn_ratelimited("wl: refusing the connection: protected management frames (802.11w) are required, "
		                    "but only WPA3-SAE supports them with this driver; use WPA3 or set PMF to optional/disabled\n");
		return -EOPNOTSUPP;
	}

	WL_DBG(("ie (%p), ie_len (%zd)\n", sme->ie, sme->ie_len));
	/* Capture wpa_supplicant's assoc IEs (RSN + RSNXE) so the firmware can emit them
	 * verbatim in the SAE assoc-req (see wl_re_drive_assoc). */
	wl_sae.assoc_ie_len = 0;
	wl_sae.pmf_active = false;   /* re-armed when the IGTK installs after the 4-way */
	if (sme->ie && sme->ie_len) {
		/* Only the RSN (+RSNX) elements: the blob pastes this buffer into its assoc request next to its
		 * own capability IEs, so wpa_supplicant's Extended Capabilities / Supported Operating Classes
		 * would be sent twice and confuse the AP. */
		const u8 *ie = sme->ie;
		size_t left = sme->ie_len;

		while (left >= 2 && (size_t)ie[1] + 2 <= left) {
			size_t el = (size_t)ie[1] + 2;

			if ((ie[0] == WLAN_EID_RSN || ie[0] == WLAN_EID_RSNX) &&
			    wl_sae.assoc_ie_len + el <= sizeof(wl_sae.assoc_ie)) {
				memcpy(wl_sae.assoc_ie + wl_sae.assoc_ie_len, ie, el);
				wl_sae.assoc_ie_len += (u16)el;
			}
			ie += el;
			left -= el;
		}
		if (re_verbose)
			print_hex_dump(KERN_ERR, "re connIE: ", DUMP_PREFIX_OFFSET, 16, 1,
			               sme->ie, sme->ie_len > 96 ? 96 : (int)sme->ie_len, false);
	}

	/* Decide ONCE whether this is a WPA3-SAE connection (also for WPA2/WPA3 transition APs:
	 * wpa_supplicant offers SAE there, and we must not let the blob fall back to PSK). */
	if (!wl_sae.inited) {
		INIT_DELAYED_WORK(&wl_sae.work, wl_sae_ext_auth_work);
		INIT_WORK(&wl_sae.saq_work, wl_re_saq_work);
		INIT_DELAYED_WORK(&wl_sae.assoc_wd, wl_sae_assoc_wd_work);
		INIT_WORK(&wl_sae.dd_work, wl_re_dd_work);
		INIT_DELAYED_WORK(&wl_sae.saq_chk, wl_re_saq_chk_work);
		INIT_DELAYED_WORK(&wl_sae.retry_work, wl_sae_retry_work);
		INIT_DELAYED_WORK(&wl_sae.join_work, wl_sae_join_work);
		INIT_DELAYED_WORK(&wl_sae.hs_wd, wl_sae_hs_wd_work);
		atomic_set(&wl_sae.txfail_cnt, 0);
		atomic64_set(&wl_sae.tx_pn, 0x1000000);   /* start well above any short-session data PN */
		wl_sae.inited = true;
	}
	wl_sae.dev = dev;
	cancel_delayed_work_sync(&wl_sae.work);       /* a start scheduled by a previous attempt */
	cancel_delayed_work_sync(&wl_sae.retry_work);
	cancel_delayed_work_sync(&wl_sae.join_work);
	cancel_delayed_work_sync(&wl_sae.hs_wd);
	wl_sae.assoc_status = 0;
	wl_sae.retries = 0;
	wl_sae.ptk_done = false;
	cancel_delayed_work_sync(&wl_sae.assoc_wd);   /* stale watchdog of a previous attempt */
	cancel_delayed_work_sync(&wl_sae.saq_chk);
	wl_sae.saq_pending = false;
	wl_sae.rx_mgmt_pn = 0;
	wl_sae.rx_ba_pn = 0;
	wl_re_release_assoc_ie();   /* a WPA2 connect must not reuse the previous SAE RSN IE */
	wl_sae.sae_conn = wl_sme_is_sae(sme);
	wl_sae.sae_ok = false;
	wl_sae.freq = sme->channel ? sme->channel->center_freq : 0;

	err = wl_set_auth_type(dev, sme);
	if (err)
		return err;

	err = wl_set_wpa_version(dev, sme);
	if (err)
		return err;

	err = wl_set_set_cipher(dev, sme);
	if (err)
		return err;

	err = wl_set_key_mgmt(dev, sme);
	if (err)
		return err;
	if (re_verbose) {
		s32 wa = -1;
		wl_dev_intvar_get(dev, "wpa_auth", &wa);
		re_log("re: connect: wpa_versions=0x%x -> wpa_auth=0x%x\n", sme->crypto.wpa_versions, wa);
	}

	err = wl_set_set_sharedkey(dev, sme);
	if (err)
		return err;

	valc = 1;
	wl_dev_bufvar_set(dev, "wsec_restrict", &valc, 1);

	/* The blob can only (re)associate with Open auth + its own PSK RSN IE. For SAE keep it
	 * from roaming on its own, so a transition-mode AP can't silently pull us onto WPA2-PSK
	 * (the guards in wl_bss_connect_done()/wl_notify_roaming_status() are the backstop).
	 * Non-SAE connections get the stock behaviour back. Failures are non-fatal. */
	if (wl_dev_intvar_set(dev, "roam_off", wl_sae.sae_conn ? 1 : 0))
		re_log("re: roam_off failed\n");

	if (sme->bssid) {
		memcpy(wl->profile->bssid, sme->bssid, ETHER_ADDR_LEN);
	}
	else {
		memset(wl->profile->bssid, 0, ETHER_ADDR_LEN);
	}

	memset(&join_params, 0, sizeof(join_params));
	join_params_size = sizeof(join_params.ssid);

	join_params.ssid.SSID_len = min(sizeof(join_params.ssid.SSID), sme->ssid_len);
	memcpy(&join_params.ssid.SSID, sme->ssid, join_params.ssid.SSID_len);
	join_params.ssid.SSID_len = htod32(join_params.ssid.SSID_len);
	/* Pin the target AP when known so the firmware does a DIRECTED join instead of a full
	 * multi-channel scan. The host-driven SAE breaks if the radio leaves the AP's channel
	 * mid-exchange, so a directed join (single channel) is what makes it complete. */
	if (sme->bssid)
		memcpy(&join_params.params.bssid, sme->bssid, ETHER_ADDR_LEN);
	else
		memcpy(&join_params.params.bssid, &ether_bcast, ETHER_ADDR_LEN);

	memcpy(wl->profile->ssid.SSID, &join_params.ssid.SSID, join_params.ssid.SSID_len);
	wl->profile->ssid.SSID_len = join_params.ssid.SSID_len;

	wl_ch_to_chanspec(sme->channel, &join_params, &join_params_size);
	re_log("re: join bssid=%pM chan=%px freq=%d jpsize=%zu\n",
	       (u8 *)&join_params.params.bssid, sme->channel,
	       sme->channel ? sme->channel->center_freq : 0, join_params_size);
	WL_DBG(("join_param_size %u\n", (unsigned int)join_params_size));

	if (join_params.ssid.SSID_len < IEEE80211_MAX_SSID_LEN) {
		WL_DBG(("ssid \"%s\", len (%d)\n", join_params.ssid.SSID,
		        join_params.ssid.SSID_len));
	}
	if (join_params_size <= sizeof(wl_sae.join_buf)) {
		memcpy(wl_sae.join_buf, &join_params, join_params_size);
		wl_sae.join_len = join_params_size;
	} else {
		wl_sae.join_len = 0;
	}
	/* M3: for WPA3-SAE the exchange is run by userspace (wpa_supplicant) via .external_auth and
	 * .mgmt_tx; it is armed and scheduled in wl_sae_issue_join(). */
	if (wl_sae.sae_conn) {
		/* NetworkManager connects by SSID with NO fixed BSSID; the firmware picks the AP
		 * and we capture its MAC from __wrap_wlc_sendauth (arg2). Only seed from sme->bssid
		 * if it was given (e.g. a standalone wpa_supplicant config with bssid=). */
		if (sme->bssid)
			memcpy(wl_sae.bssid, sme->bssid, ETH_ALEN);
		else
			memset(wl_sae.bssid, 0, ETH_ALEN);
		wl_sae.ssid.ssid_len = min_t(size_t, sme->ssid_len, sizeof(wl_sae.ssid.ssid));
		memcpy(wl_sae.ssid.ssid, sme->ssid, wl_sae.ssid.ssid_len);
	}

	/* Quiet time after the last disconnect: the AP needs a moment to finish with the old
	 * association. Wait for it from a delayed work rather than sleeping here (see wl_sae_join_work). */
	if (wl_sae.join_len && wl_sae.last_disc &&
	    time_before(jiffies, wl_sae.last_disc + msecs_to_jiffies(WL_MIN_REJOIN_GAP_MS))) {
		unsigned long delay = wl_sae.last_disc + msecs_to_jiffies(WL_MIN_REJOIN_GAP_MS) - jiffies;

		re_log("re: deferring the join by %u ms (quiet time after the last disconnect)\n",
		       jiffies_to_msecs(delay));
		schedule_delayed_work(&wl_sae.join_work, delay);
		return 0;
	}

	if (!wl_sae.join_len) {   /* request too large for the retry buffer: send it directly */
		err = wl_dev_ioctl(dev, WLC_SET_SSID, &join_params, join_params_size);
		if (err) {
			WL_ERR(("error (%d)\n", err));
			return err;
		}
		set_bit(WL_STATUS_CONNECTING, &wl->status);
		re_log("re: CONNECTING set\n");
		if (wl_sae.sae_conn) {
			wl_sae.stub_seen = false;
			wl_sae.armed = 1;
			schedule_delayed_work(&wl_sae.work, msecs_to_jiffies(WL_SAE_START_FALLBACK_MS));
		}
		return 0;
	}

	err = wl_sae_issue_join(dev);
	if (err)
		WL_ERR(("error (%d)\n", err));
	return err;
}

static s32
wl_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev, u16 reason_code)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	scb_val_t scbval;
	s32 err = 0;

	bool pmf = wl_sae.pmf_active;

	wl_sae.last_disc = jiffies;
	wl_sae.armed = 0;       /* disarm SAE hooks on disconnect */
	if (wl_sae.inited) {
		cancel_delayed_work_sync(&wl_sae.assoc_wd);
		cancel_delayed_work_sync(&wl_sae.saq_chk);
		cancel_delayed_work_sync(&wl_sae.retry_work);
		cancel_delayed_work_sync(&wl_sae.join_work);
		cancel_delayed_work_sync(&wl_sae.hs_wd);
	}
	wl_sae.saq_pending = false;
	wl_re_release_assoc_ie();
	wl_sae.sae_conn = false;
	wl_sae.sae_ok = false;
	wl_sae.pmf_active = false;
	wl_sae.bsscfg = NULL;
	WL_DBG(("Reason %d\n", reason_code));

	if (wl->profile->active) {
		/* With 802.11w the AP ignores the blob's unprotected deauth/disassoc and keeps a stale
		 * association, which then makes the next join to that BSS stall or get rejected. Tell it
		 * properly with a CCMP-protected deauth (software CCMP, like the SA-Query response). */
		if (pmf && wl_sae.tk_set) {
			int try, rc;

			/* The blob gives up on a frame after a few un-ACKed attempts and only tells us with a
			 * WLC_E_TXFAIL event. A deauth the AP never received leaves it holding the old
			 * association (-> "try again later" on the next join), so look for that event and
			 * retransmit before tearing the radio state down. */
			for (try = 0; try < 3; try++) {
				int before = atomic_read(&wl_sae.txfail_cnt);

				rc = wl_re_send_protected_deauth(dev, reason_code ? reason_code :
				                                 WLAN_REASON_DEAUTH_LEAVING);
				re_log("re: protected deauth #%d -> %d\n", try + 1, rc);
				if (rc)
					break;
				msleep(WL_DEAUTH_SETTLE_MS);   /* time to leave the air, and for a TXFAIL to be reported */
				if (atomic_read(&wl_sae.txfail_cnt) == before)
					break;          /* no TX failure reported: the AP ACKed it */
				re_log("re: protected deauth was not acknowledged -> retransmitting\n");
			}
			wl_sae.tk_set = false;
		}
		memcpy(&scbval.ea, &wl->bssid, ETHER_ADDR_LEN);
		scbval.val = htod32(reason_code);
		err = wl_dev_ioctl(dev, WLC_DISASSOC, &scbval, sizeof(scbval));
		if (err) {
			WL_ERR(("error (%d)\n", err));
			return err;
		}
	} else {
	    return -EIO;
	}

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, int radio_idx,
                         enum nl80211_tx_power_setting type, s32 mbm)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
                         enum nl80211_tx_power_setting type, s32 mbm)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, enum nl80211_tx_power_setting type, s32 mbm)
#else
#define NL80211_TX_POWER_AUTOMATIC TX_POWER_AUTOMATIC
#define NL80211_TX_POWER_LIMITED TX_POWER_LIMITED
#define NL80211_TX_POWER_FIXED TX_POWER_FIXED
static s32
wl_cfg80211_set_tx_power(struct wiphy *wiphy, enum tx_power_setting type, s32 mbm)
#endif
{

	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct net_device *ndev = wl_to_ndev(wl);
	s32 err = 0;
	s32 disable = 0;
	s32 dbm = MBM_TO_DBM(mbm);
	s32 qdbm = dbm * 4;

	switch (type) {
	case NL80211_TX_POWER_AUTOMATIC:
		break;
	case NL80211_TX_POWER_LIMITED:
		if (dbm < 0) {
			WL_ERR(("TX_POWER_LIMITTED - dbm is negative\n"));
			return -EINVAL;
		}
		break;
	case NL80211_TX_POWER_FIXED:
		if (dbm < 0) {
			WL_ERR(("TX_POWER_FIXED - dbm is negative..\n"));
			return -EINVAL;
		}
		break;
	}

	qdbm = (qdbm > 127) ? 127 : qdbm;
	qdbm |= WL_TXPWR_OVERRIDE;

	disable = WL_RADIO_SW_DISABLE << 16;
	disable = htod32(disable);
	err = wl_dev_ioctl(ndev, WLC_SET_RADIO, &disable, sizeof(disable));
	if (err) {
		WL_ERR(("WLC_SET_RADIO error (%d)\n", err));
		return err;
	}

	err = wl_dev_intvar_set(ndev, "qtxpower", qdbm);
	if (err) {
		WL_ERR(("qtxpower error (%d)\n", err));
		return err;
	}
	wl->conf->tx_power = dbm;

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, int radio_idx, unsigned int link_id, s32 *dbm)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, u32 /*link_id*/, s32 *dbm)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev, s32 *dbm)
#else
static s32 wl_cfg80211_get_tx_power(struct wiphy *wiphy, s32 *dbm)
#endif
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct net_device *ndev = wl_to_ndev(wl);
	s32 txpwrdbm;
	u8 result;
	s32 err = 0;

	err = wl_dev_intvar_get(ndev, "qtxpower", &txpwrdbm);
	if (err) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}
	result = (u8) (txpwrdbm & ~WL_TXPWR_OVERRIDE);
	*dbm = (s32) result / 4;

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static s32
wl_cfg80211_config_default_key(struct wiphy *wiphy,
	struct net_device *dev, int link_id, u8 key_idx, bool unicast,
	bool multicast)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
static s32
wl_cfg80211_config_default_key(struct wiphy *wiphy,
	struct net_device *dev, u8 key_idx, bool unicast, bool multicast)
#else
static s32
wl_cfg80211_config_default_key(struct wiphy *wiphy,
	struct net_device *dev, u8 key_idx)
#endif
{
	u32 index;
	s32 err = 0;

	WL_DBG(("key index (%d)\n", key_idx));

	index = (u32) key_idx;
	index = htod32(index);
	err = wl_dev_ioctl(dev, WLC_SET_KEY_PRIMARY, &index, sizeof(index));
	re_log("re: set_default_key idx=%u -> %d\n", key_idx, err);
	if (err) {
		WL_DBG(("error (%d)\n", err));
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
static s32
wl_cfg80211_add_key(struct wiphy *wiphy, struct wireless_dev *wdev,
                    int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
                    struct key_params *params)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static s32
wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
                    int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
                    struct key_params *params)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static s32
wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
                    u8 key_idx, bool pairwise, const u8 *mac_addr, struct key_params *params)
#else
static s32
wl_cfg80211_add_key(struct wiphy *wiphy, struct net_device *dev,
                    u8 key_idx, const u8 *mac_addr, struct key_params *params)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
	struct net_device *dev = wdev->netdev;
#endif
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	struct wl_wsec_key key;
	s32 secval, secnew = 0;
	s32 err = 0;

	WL_DBG(("key index %u    len %u\n", (unsigned)key_idx, params->key_len));

	/* 802.11w IGTK (BIP-CMAC-128, key idx 4/5): the BCM4360 HW key engine has no BIP slot
	 * and the blob caps key index at 3, so WLC_SET_KEY returns -22; wpa_supplicant then aborts
	 * the connection during GROUP_HANDSHAKE (reason=1). Accept it in software (no HW install)
	 * so the link comes up -- the PTK/GTK (data path) are installed normally. Management-frame
	 * protection is SW/best-effort (M3.4). */
	if (params->cipher == WLAN_CIPHER_SUITE_AES_CMAC || key_idx >= 4) {
		if (params->key && params->key_len == 16) {
			memcpy(wl_sae.igtk, params->key, 16);
			wl_sae.igtk_keyid = key_idx;
			if (params->seq && params->seq_len >= 6)
				memcpy(wl_sae.igtk_ipn, params->seq, 6);
			wl_sae.pmf_active = true;   /* MFP is now active -> enforce SW PMF on RX */
		}
		re_log("re add_key: IGTK/BIP (idx=%u cipher=0x%x) stored SW; PMF active (no HW BIP)\n",
		        (unsigned)key_idx, params->cipher);
		return 0;
	}
	/* Capture the pairwise CCMP temporal key (PTK TK) for the SW SA-Query crypto. */
	if (params->cipher == WLAN_CIPHER_SUITE_CCMP && pairwise &&
	    params->key && params->key_len == 16) {
		memcpy(wl_sae.tk, params->key, 16);
		wl_sae.tk_set = true;
		wl_re_fast_key(wl_sae.tk);
		re_log("re add_key: captured pairwise CCMP TK for SW mgmt crypto\n");
		wl_sae.ptk_done = true;
		cancel_delayed_work(&wl_sae.hs_wd);
	}

	memset(&key, 0, sizeof(key));

	key.index = (u32) key_idx;

	switch (params->cipher) {
	case WLAN_CIPHER_SUITE_WEP40:
		key.algo = CRYPTO_ALGO_WEP1;
		secnew = WEP_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_WEP40\n"));
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		key.algo = CRYPTO_ALGO_WEP128;
		secnew = WEP_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_WEP104\n"));
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		key.algo = CRYPTO_ALGO_TKIP;
		secnew = TKIP_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_TKIP\n"));
		break;
	case WLAN_CIPHER_SUITE_AES_CMAC:
		key.algo = CRYPTO_ALGO_AES_CCM;
		secnew = AES_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_AES_CMAC\n"));
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		key.algo = CRYPTO_ALGO_AES_CCM;
		secnew = AES_ENABLED;
		WL_DBG(("WLAN_CIPHER_SUITE_CCMP\n"));
		break;
	default:
		WL_ERR(("Invalid cipher (0x%x)\n", params->cipher));
		return -EINVAL;
	}

	if (mac_addr) {
		if (!ETHER_ISMULTI(mac_addr)) {
			memcpy((char *)&key.ea, (void *)mac_addr, ETHER_ADDR_LEN);
		}
	}

	key.len = (u32) params->key_len;
	if (key.len > sizeof(key.data)) {
		WL_ERR(("Too long key length (%u)\n", key.len));
		return -EINVAL;
	}
	memcpy(key.data, params->key, key.len);

	if (params->cipher == WLAN_CIPHER_SUITE_TKIP) {
		u8 keybuf[8];
		memcpy(keybuf, &key.data[24], sizeof(keybuf));
		memcpy(&key.data[24], &key.data[16], sizeof(keybuf));
		memcpy(&key.data[16], keybuf, sizeof(keybuf));
	}

	if (params->seq_len) { 
		u8 *ivptr;
		if (params->seq_len != 6) {
			WL_ERR(("seq_len %d is unexpected, check implementation.\n",
				params->seq_len));
		}
		ivptr = (u8 *) params->seq;
		key.rxiv.hi = (ivptr[5] << 24) | (ivptr[4] << 16) | (ivptr[3] << 8) | ivptr[2];
		key.rxiv.lo = (ivptr[1] << 8) | ivptr[0];
		key.iv_initialized = true;
	}

	{
		s32 wsecv = -1, wav = -1;
		wl_dev_intvar_get(dev, "wsec", &wsecv);
		wl_dev_intvar_get(dev, "wpa_auth", &wav);
		re_log("re add_key: idx=%u algo=%u len=%u flags=0x%x ea=%pM pairwise=%d "
		       "wsec=0x%x wpa_auth=0x%x sizeof_key=%zu\n",
		       key.index, key.algo, key.len, key.flags, &key.ea, mac_addr ? 1 : 0,
		       wsecv, wav, sizeof(key));
	}
	key_endian_to_device(&key);
	if (wl->passive) {
		schedule();
	}
	err = wl_dev_ioctl(dev, WLC_SET_KEY, &key, sizeof(key));
	if (err) {
		WL_ERR(("WLC_SET_KEY error (%d) idx=%u algo=%u len=%u\n",
		        err, dtoh32(key.index), key.algo, dtoh32(key.len)));
		return err;
	}

	if ((err = wl_dev_intvar_get(dev, "wsec", &secval))) {
		return err;
	}
	if (secnew == WEP_ENABLED) {
		secval &= ~(TKIP_ENABLED | AES_ENABLED);
	}
	else {
		secval &= ~(WEP_ENABLED);
	}
	secval |= secnew;
	WL_DBG(("set wsec to %d\n", secval));
	err = wl_dev_intvar_set(dev, "wsec", secval);
	if (err) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}

	if (mac_addr) {
		wl->profile->sec.cipher_pairwise = params->cipher;
	}
	else {
		wl->profile->sec.cipher_group = params->cipher;
	}

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
static s32
wl_cfg80211_del_key(struct wiphy *wiphy, struct wireless_dev *wdev,
                    int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static s32
wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
                    int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static s32
wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
                    u8 key_idx, bool pairwise, const u8 *mac_addr)
#else
static s32
wl_cfg80211_del_key(struct wiphy *wiphy, struct net_device *dev,
                    u8 key_idx, const u8 *mac_addr)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
	struct net_device *dev = wdev->netdev;
#endif
	struct wl_wsec_key key;
	s32 err = 0;

	WL_DBG(("key index (%d)\n", key_idx));

	memset(&key, 0, sizeof(key));

	key.index = (u32) key_idx;
	key.len = 0;
	if (mac_addr) {
		if (!ETHER_ISMULTI(mac_addr)) {
			memcpy((char *)&key.ea, (void *)mac_addr, ETHER_ADDR_LEN);
		}
	}
	key.algo = CRYPTO_ALGO_OFF;

	key_endian_to_device(&key);
	err = wl_dev_ioctl(dev, WLC_SET_KEY, &key, sizeof(key));
	if (err) {
		if (err == -EINVAL) {
			if (key.index >= DOT11_MAX_DEFAULT_KEYS) {

				WL_DBG(("invalid key index (%d)\n", key_idx));
			}
		} else {
			WL_ERR(("WLC_SET_KEY error (%d)\n", err));
		}
		return err;
	}

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
static s32
wl_cfg80211_get_key(struct wiphy *wiphy, struct wireless_dev *wdev,
                    int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
                    void *cookie,
                    void (*callback) (void *cookie, struct key_params * params))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static s32
wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
                    int link_id, u8 key_idx, bool pairwise, const u8 *mac_addr,
                    void *cookie,
                    void (*callback) (void *cookie, struct key_params * params))
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static s32
wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
                    u8 key_idx, bool pairwise, const u8 *mac_addr, void *cookie,
                    void (*callback) (void *cookie, struct key_params * params))
#else
static s32
wl_cfg80211_get_key(struct wiphy *wiphy, struct net_device *dev,
                    u8 key_idx, const u8 *mac_addr, void *cookie,
                    void (*callback) (void *cookie, struct key_params * params))
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
	struct net_device *dev = wdev->netdev;
#endif
	struct key_params params;
	struct wl_wsec_key key;
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct wl_cfg80211_security *sec;
	s32 wsec;
	s32 err = 0;

	WL_DBG(("key index (%d)\n", key_idx));

	memset(&params, 0, sizeof(params));

	memset(&key, 0, sizeof(key));
	key.index = key_idx;
	key_endian_to_device(&key);

	if ((err = wl_dev_ioctl(dev, WLC_GET_KEY, &key, sizeof(key)))) {
		return err;
	}
	key_endian_to_host(&key);

	params.key_len = (u8) min_t(u8, DOT11_MAX_KEY_SIZE, key.len);
	memcpy((char *)params.key, key.data, params.key_len);

	if ((err = wl_dev_ioctl(dev, WLC_GET_WSEC, &wsec, sizeof(wsec)))) {
		return err;
	}
	wsec = dtoh32(wsec);
	switch (wsec) {
	case WEP_ENABLED:
		sec = &wl->profile->sec;
		if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP40) {
			params.cipher = WLAN_CIPHER_SUITE_WEP40;
			WL_DBG(("WLAN_CIPHER_SUITE_WEP40\n"));
		} else if (sec->cipher_pairwise & WLAN_CIPHER_SUITE_WEP104) {
			params.cipher = WLAN_CIPHER_SUITE_WEP104;
			WL_DBG(("WLAN_CIPHER_SUITE_WEP104\n"));
		}
		break;
	case TKIP_ENABLED:
		params.cipher = WLAN_CIPHER_SUITE_TKIP;
		WL_DBG(("WLAN_CIPHER_SUITE_TKIP\n"));
		break;
	case AES_ENABLED:
		params.cipher = WLAN_CIPHER_SUITE_AES_CMAC;
		WL_DBG(("WLAN_CIPHER_SUITE_AES_CMAC\n"));
		break;
	default:
		WL_ERR(("Invalid algo (0x%x)\n", wsec));
		return -EINVAL;
	}

	callback(cookie, &params);
	return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
static s32
wl_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
                        u8 *mac, struct station_info *sinfo)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
static s32
wl_cfg80211_get_station(struct wiphy *wiphy, struct wireless_dev *wdev,
                        const u8 *mac, struct station_info *sinfo)
#else
static s32
wl_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
                        const u8 *mac, struct station_info *sinfo)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 1, 0)
	struct net_device *dev = wdev->netdev;
#endif
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	scb_val_t scb_val;

	int rssi;
	s32 rate;
	s32 err = 0;

	if (memcmp(mac, wl->profile->bssid, ETHER_ADDR_LEN)) {
		WL_ERR(("Wrong Mac address, mac = %pM   profile =%pM\n", mac, wl->profile->bssid));
		return -ENOENT;
	}

	err = wl_dev_ioctl(dev, WLC_GET_RATE, &rate, sizeof(rate));
	if (err) {
		WL_DBG(("Could not get rate (%d)\n", err));
	} else {
		rate = dtoh32(rate);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		sinfo->filled |= BIT(NL80211_STA_INFO_TX_BITRATE);
#else
		sinfo->filled |= STATION_INFO_TX_BITRATE;
#endif
		sinfo->txrate.legacy = rate * 5;
		WL_DBG(("Rate %d Mbps\n", (rate / 2)));
	}

	if (test_bit(WL_STATUS_CONNECTED, &wl->status)) {
		memset(&scb_val, 0, sizeof(scb_val));
		err = wl_dev_ioctl(dev, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t));
		if (err) {
			WL_DBG(("Could not get rssi (%d)\n", err));
			return err;
		}
		rssi = dtoh32(scb_val.val);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
		sinfo->filled |= BIT(NL80211_STA_INFO_SIGNAL);
#else
		sinfo->filled |= STATION_INFO_SIGNAL;
#endif
		sinfo->signal = rssi;
		WL_DBG(("RSSI %d dBm\n", rssi));
	}

	return err;
}

static s32
wl_cfg80211_set_power_mgmt(struct wiphy *wiphy, struct net_device *dev,
                           bool enabled, s32 timeout)
{
	s32 pm;
	s32 err = 0;

	/* NOTICE: Use PM_FORCE_OFF, otherwise powersaving will turn itself
	 * ON again (PM_FAST) when on battery power. */
	pm = enabled ? PM_FAST : PM_FORCE_OFF;
	pm = htod32(pm);
	WL_DBG(("power save %s\n", (pm ? "enabled" : "disabled")));
	err = wl_dev_ioctl(dev, WLC_SET_PM, &pm, sizeof(pm));
	if (err) {
		if (err == -ENODEV)
			WL_DBG(("net_device is not ready yet\n"));
		else
			WL_ERR(("error (%d)\n", err));
		return err;
	}
	return err;
}

static __used s32
wl_update_pmklist(struct net_device *dev, struct wl_cfg80211_pmk_list *pmk_list, s32 err)
{
	int i, j;

	WL_DBG(("No of elements %d\n", pmk_list->pmkids.npmkid));
	for (i = 0; i < pmk_list->pmkids.npmkid; i++) {
		WL_DBG(("PMKID[%d]: %pM =\n", i,
			&pmk_list->pmkids.pmkid[i].BSSID));
		for (j = 0; j < WPA2_PMKID_LEN; j++) {
			WL_DBG(("%02x\n", pmk_list->pmkids.pmkid[i].PMKID[j]));
		}
	}
	if (!err) {
		err = wl_dev_bufvar_set(dev, "pmkid_info", (char *)pmk_list, sizeof(*pmk_list));
	}

	return err;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)

static s32
wl_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *dev,
                      struct cfg80211_pmksa *pmksa)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	s32 err = 0;
	int i;

	for (i = 0; i < wl->pmk_list->pmkids.npmkid; i++)
		if (!memcmp(pmksa->bssid, &wl->pmk_list->pmkids.pmkid[i].BSSID, ETHER_ADDR_LEN))
			break;
	if (i < WL_NUM_PMKIDS_MAX) {
		memcpy(&wl->pmk_list->pmkids.pmkid[i].BSSID, pmksa->bssid, ETHER_ADDR_LEN);
		memcpy(&wl->pmk_list->pmkids.pmkid[i].PMKID, pmksa->pmkid, WPA2_PMKID_LEN);
		if (i == wl->pmk_list->pmkids.npmkid)
			wl->pmk_list->pmkids.npmkid++;
	} else {
		err = -EINVAL;
	}
	WL_DBG(("set_pmksa,IW_PMKSA_ADD - PMKID: %pM =\n",
		&wl->pmk_list->pmkids.pmkid[wl->pmk_list->pmkids.npmkid].BSSID));
	for (i = 0; i < WPA2_PMKID_LEN; i++) {
		WL_DBG(("%02x\n",
			wl->pmk_list->pmkids.pmkid[wl->pmk_list->pmkids.npmkid].PMKID[i]));
	}

	err = wl_update_pmklist(dev, wl->pmk_list, err);

	return err;
}

static s32
wl_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *dev,
                      struct cfg80211_pmksa *pmksa)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	struct _pmkid_list pmkid;
	s32 err = 0;
	int i;

	memcpy(&pmkid.pmkid[0].BSSID, pmksa->bssid, ETHER_ADDR_LEN);
	memcpy(&pmkid.pmkid[0].PMKID, pmksa->pmkid, WPA2_PMKID_LEN);

	WL_DBG(("del_pmksa,IW_PMKSA_REMOVE - PMKID: %pM =\n",
		&pmkid.pmkid[0].BSSID));
	for (i = 0; i < WPA2_PMKID_LEN; i++) {
		WL_DBG(("%02x\n", pmkid.pmkid[0].PMKID[i]));
	}

	for (i = 0; i < wl->pmk_list->pmkids.npmkid; i++)
		if (!memcmp(pmksa->bssid, &wl->pmk_list->pmkids.pmkid[i].BSSID, ETHER_ADDR_LEN))
			break;

	if ((wl->pmk_list->pmkids.npmkid > 0) && (i < wl->pmk_list->pmkids.npmkid)) {
		memset(&wl->pmk_list->pmkids.pmkid[i], 0, sizeof(pmkid_t));
		for (; i < (wl->pmk_list->pmkids.npmkid - 1); i++) {
			memcpy(&wl->pmk_list->pmkids.pmkid[i].BSSID,
			       &wl->pmk_list->pmkids.pmkid[i + 1].BSSID, ETHER_ADDR_LEN);
			memcpy(&wl->pmk_list->pmkids.pmkid[i].PMKID,
			       &wl->pmk_list->pmkids.pmkid[i + 1].PMKID, WPA2_PMKID_LEN);
		}
		wl->pmk_list->pmkids.npmkid--;
	} else {
		err = -EINVAL;
	}

	err = wl_update_pmklist(dev, wl->pmk_list, err);

	return err;

}

static s32
wl_cfg80211_flush_pmksa(struct wiphy *wiphy, struct net_device *dev)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	s32 err = 0;

	memset(wl->pmk_list, 0, sizeof(*wl->pmk_list));
	err = wl_update_pmklist(dev, wl->pmk_list, err);
	return err;

}

#endif  

#ifdef CONFIG_PM
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)

static int
wl_wowl_ind_wake_reason(struct wl_cfg80211_priv *wl, struct cfg80211_wowlan_wakeup *wakeup)
{
	wl_wowl_wakeind_t wowl_ind;
	s32 err;

	err = wl_dev_bufvar_get(wl_to_ndev(wl), "wowl_wakeind",
		(s8 *)&wowl_ind, sizeof(wowl_ind));
	if (err != 0) {
		WL_ERR(("Unable to get wake reason, err = %d\n", err));
		return -1;
	}

	if (wowl_ind.ucode_wakeind == 0) {
		WL_DBG(("System woke, but not by us\n"));
		return 0;
	}
	WL_DBG(("wake reason is 0x%x\n", wowl_ind.ucode_wakeind));

	if (wowl_ind.ucode_wakeind & WL_WOWL_MAGIC) {
		WL_ERR(("WOWLAN Woke for: Magic Pkt\n"));
		wakeup->magic_pkt = true;
	}
	if (wowl_ind.ucode_wakeind & WL_WOWL_DIS) {
		WL_ERR(("WOWLAN Woke for: Disconnect\n"));
		wakeup->disconnect = true;
	}
	if (wowl_ind.ucode_wakeind & WL_WOWL_BCN) {
		WL_ERR(("WOWLAN Woke for: Beacon Loss\n"));
		wakeup->disconnect = true;
	}
	if (wowl_ind.ucode_wakeind & WL_WOWL_GTK_FAILURE) {
		WL_ERR(("WOWLAN Woke for: GTK failure\n"));
		wakeup->gtk_rekey_failure = true;
	}
	if (wowl_ind.ucode_wakeind & WL_WOWL_EAPID) {
		WL_ERR(("WOWLAN Woke for: EAP identify request\n"));
		wakeup->eap_identity_req = true;
	}
	if (wowl_ind.ucode_wakeind & WL_WOWL_M1) {
		WL_ERR(("WOWLAN Woke for: 4-way handshake request\n"));
		wakeup->four_way_handshake = true;
	}
	return 1;
}
#endif 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
static int
wl_cfg80211_rekey(struct wiphy *wiphy, struct net_device *ndev,
        struct cfg80211_gtk_rekey_data *data)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	wlc_rekey_info_t rekey;
	s32 err;

	if (!wl->offloads) {
		return 0;
	}

	memset(&rekey, 0, sizeof(rekey));
	memcpy(&rekey.kek, data->kek, WLC_KEK_LEN);
	memcpy(&rekey.kck, data->kck, WLC_KCK_LEN);
	memcpy(&rekey.replay_counter, data->replay_ctr, WLC_REPLAY_CTR_LEN);
	WL_INF(("Send down replay counter %x%x%x%x%x%x%x%x\n",
		rekey.replay_counter[0], rekey.replay_counter[1], rekey.replay_counter[2],
		rekey.replay_counter[3], rekey.replay_counter[4], rekey.replay_counter[5],
		rekey.replay_counter[6], rekey.replay_counter[7]));

	err = wl_dev_bufvar_set(wl_to_ndev(wl), "wowl_replay", (s8 *)&rekey, sizeof(rekey));
	if (err) {
		WL_ERR(("Error calling wowl_set_key\n"));
		return err;
	}
	return err;
}
#endif 

static int wl_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wowlan)
{
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	uint wowl = 0;
	s32 err;

	if (!wowlan) {
		WL_DBG(("No wowlan requested\n"));
		return 0;
	}
	if (!test_bit(WL_STATUS_CONNECTED, &wl->status)) {
		WL_INF(("No wowl when not associated.\n"));
		return 0;
	}

	err = wl_dev_intvar_get(wl_to_ndev(wl), "wowl", &wowl);
	if (err) {
		WL_ERR(("Error fetching WOWL %d\n", err));
	}
	if (wowlan->disconnect) {
		WL_INF(("Requesting wake on Disconnect\n"));
		wowl |= WL_WOWL_DIS | WL_WOWL_BCN;
	}
	if (wowlan->magic_pkt) {
		WL_INF(("Requesting wake on Magic Pkt\n"));
		wowl |= WL_WOWL_MAGIC;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	if (wowlan->gtk_rekey_failure) {
		WL_INF(("Requesting wake GTK rekey failure Pkt\n"));
		wowl |= WL_WOWL_GTK_FAILURE;
	}
	if (wowlan->four_way_handshake) {
		WL_INF(("Requesting wake on 4way handshake request\n"));
		wowl |= WL_WOWL_M1;
	}
#endif 

	wowl |= WL_WOWL_KEYROT;

	err = wl_dev_intvar_set(wl_to_ndev(wl), "wowl", wowl);
	if (err) {
		WL_ERR(("Error enabling WOWL %d\n", err));
	}

	return err;
}
#else 
static int wl_cfg80211_suspend(struct wiphy *wiphy)
{
	return 0;
}
#endif 

static int wl_cfg80211_resume(struct wiphy *wiphy)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	struct wl_cfg80211_priv *wl = wiphy_to_wl(wiphy);
	wlc_rekey_info_t *rekey = (wlc_rekey_info_t *)wl->extra_buf;
	s32 err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	struct cfg80211_wowlan_wakeup wakeup;
	int result;

	memset(&wakeup, 0, sizeof(wakeup));
	wakeup.pattern_idx = -1;

	result = wl_wowl_ind_wake_reason(wl, &wakeup);
	switch (result) {
		case -1: 
			break;
		case 0:	
			cfg80211_report_wowlan_wakeup(wl_to_wdev(wl), NULL, GFP_KERNEL);
			break;
		case 1: 
			cfg80211_report_wowlan_wakeup(wl_to_wdev(wl), &wakeup, GFP_KERNEL);
			break;
	}
#endif 

	err = wl_dev_bufvar_get(wl_to_ndev(wl), "wowl_replay", (s8 *)rekey,
		sizeof(wlc_rekey_info_t));
	if (!err) {
		WL_INF(("Send up replay counter %x%x%x%x%x%x%x%x\n",
			rekey->replay_counter[0], rekey->replay_counter[1],
			rekey->replay_counter[2], rekey->replay_counter[3],
			rekey->replay_counter[4], rekey->replay_counter[5],
			rekey->replay_counter[6], rekey->replay_counter[7]));
		cfg80211_gtk_rekey_notify(wl_to_ndev(wl), (u8 *)&wl->bssid.octet,
			rekey->replay_counter, GFP_KERNEL);
	}
#endif 
	/* After sleeping the AP may have dropped us without us noticing: probe with an SA Query. */
	if (wl_sae.inited && wl_sae.pmf_active && wl_sae.tk_set && !wl_sae.dd_busy) {
		wl_sae.dd_kind = 1;
		wl_sae.dd_busy = true;
		schedule_work(&wl_sae.dd_work);
	}
	return 0;
}
#endif 

/* ===================== M3: host-driven WPA3-SAE bridge ===================== */
extern int wl_re_mgmt_tx(struct net_device *dev, const unsigned char *f, int flen, void *scb);
extern void wl_re_drive_assoc(struct net_device *dev, void *bsscfg, const unsigned char *mac,
                              const unsigned char *assoc_ie, unsigned int assoc_ie_len);

/* wpa_supplicant hands us a fully-built auth frame (SAE commit/confirm); TX it
 * via the firmware, then report tx-status so the SAE state machine advances. */
static int
wl_cfg80211_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
                    struct cfg80211_mgmt_tx_params *params,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 3, 0)
                    u64 cookie_in)
#else
                    u64 *cookie)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 3, 0)
	u64 cookie_val = cookie_in;
	u64 *cookie = &cookie_val;   /* cfg80211 now assigns the cookie (by value) */
#endif
	struct net_device *dev = wdev ? wdev->netdev : NULL;
	const u8 *f = params->buf;
	int flen = (int)params->len;
	u16 fc, alg = 0;
	int err;

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 3, 0)
	if (cookie)
		*cookie = (u64)(uintptr_t)f;
#endif
	if (!dev || !f || flen < 24)
		return -EINVAL;
	fc = f[0] | (f[1] << 8);
	if ((fc & 0x0c) != 0x00)            /* management frames only */
		return -EOPNOTSUPP;
	if (flen >= 26)
		alg = f[24] | (f[25] << 8);

	err = wl_re_mgmt_tx(dev, f, flen, wl_sae.scb);
	re_log("re mgmt_tx: %d-byte frame auth_alg=%u da=%pM scb=%px -> %d\n",
	        flen, alg, f + 4, wl_sae.scb, err);
	if (cookie)
		cfg80211_mgmt_tx_status(wdev, *cookie, f, flen, err == 0, GFP_KERNEL);
	return err;
}

static int
wl_cfg80211_external_auth(struct wiphy *wiphy, struct net_device *dev,
                          struct cfg80211_external_auth_params *params)
{
	re_log("re: EXTERNAL_AUTH status=%u akm=0x%x bssid=%pM bsscfg=%px\n",
	       params->status, params->key_mgmt_suite, params->bssid, wl_sae.bsscfg);
	/* SAE succeeded -> drive the firmware from auth state into association, feeding it
	 * wpa_supplicant's RSN+RSNXE so the assoc-req matches the SAE+MFP AP. */
	if (params->status == 0 && wl_sae.bsscfg) {
		wl_sae.sae_ok = true;
		re_log("re: SAE ok -> driving firmware to associate (assoc_ie_len=%u)\n",
		        wl_sae.assoc_ie_len);
		wl_re_drive_assoc(dev, wl_sae.bsscfg, wl_sae.bssid,
		                  wl_sae.assoc_ie, wl_sae.assoc_ie_len);
		schedule_delayed_work(&wl_sae.assoc_wd, msecs_to_jiffies(WL_SAE_ASSOC_TIMEOUT_MS));
	} else if (params->status != 0) {
		/* SAE failed: abort the pending firmware join NOW so it can't fall back to an
		 * Open/PSK association, and fail the connect so wpa_supplicant retries SAE. */
		struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
		scb_val_t scbval;
		re_log("re: SAE FAILED (status %u) -> aborting join\n", params->status);
		wl_sae.sae_ok = false;
		memset(&scbval, 0, sizeof(scbval));
		memcpy(&scbval.ea, wl_sae.bssid, ETHER_ADDR_LEN);
		scbval.val = htod32(WLAN_REASON_UNSPECIFIED);
		wl_dev_ioctl(dev, WLC_DISASSOC, &scbval, sizeof(scbval));
		if (test_and_clear_bit(WL_STATUS_CONNECTING, &wl->status))
			cfg80211_connect_result(dev, wl_sae.bssid, NULL, 0, NULL, 0,
			                        WLAN_STATUS_UNSPECIFIED_FAILURE, GFP_KERNEL);
	}
	wl_sae.armed = 0;       /* SAE done -> disarm the RX hook (no more auth frames) */
	return 0;
}

static void
wl_cfg80211_update_mgmt_frame_registrations(struct wiphy *wiphy,
        struct wireless_dev *wdev, struct mgmt_frame_regs *upd)
{
	/* accept all mgmt-frame registrations (wpa_supplicant registers for auth frames) */
}
/* Per-iftype mgmt tx/rx subtypes. REQUIRED: without this, cfg80211 rejects
 * wpa_supplicant's AUTH-frame registration (-EOPNOTSUPP) and it can't run
 * external-auth SAE. STATION must allow AUTH (and ACTION) tx+rx. */
static const struct ieee80211_txrx_stypes
wl_cfg80211_txrx_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = {
		.tx = BIT(IEEE80211_STYPE_AUTH >> 4) |
		      BIT(IEEE80211_STYPE_ACTION >> 4),
		.rx = BIT(IEEE80211_STYPE_AUTH >> 4) |
		      BIT(IEEE80211_STYPE_ACTION >> 4) |
		      BIT(IEEE80211_STYPE_PROBE_REQ >> 4),
	},
};

/* Hand a received SAE auth frame up to wpa_supplicant. The firmware's RX handler
 * gets only the auth body (alg/seq/status + SAE fields); rebuild the 802.11 header. */
static __maybe_unused void wl_re_rx_auth(struct net_device *dev, const unsigned short *body, unsigned int len)
{
	struct wireless_dev *wdev = dev ? dev->ieee80211_ptr : NULL;
	u8 *buf;
	if (!wdev || !body || len < 6 || len > 1024)
		return;
	buf = kmalloc(24 + len, GFP_ATOMIC);
	if (!buf)
		return;
	buf[0] = 0xb0; buf[1] = 0x00;            /* FC: mgmt / auth */
	buf[2] = 0;    buf[3] = 0;               /* duration */
	memcpy(buf + 4,  dev->dev_addr, 6);      /* DA = us */
	memcpy(buf + 10, wl_sae.bssid, 6);       /* SA = AP */
	memcpy(buf + 16, wl_sae.bssid, 6);       /* BSSID = AP */
	buf[22] = 0;   buf[23] = 0;              /* seq ctl */
	memcpy(buf + 24, body, len);             /* auth body (alg/seq/status + SAE) */
	cfg80211_rx_mgmt(wdev, wl_sae.freq ? wl_sae.freq : 2447, 0, buf, 24 + len, 0);
	re_log("re rx_auth: delivered %u-byte SAE auth body up to userspace\n", len);
	kfree(buf);
}

/* --- interpose on the firmware's auth TX/RX. The blob's call sites are repointed to
 * these __wrap_* by tools/wl_reloc.py (editing .rela.text); we chain to the real
 * (globalized) wlc_sendauth/wlc_authresp_client by name. --- */
extern long wlc_sendauth(void *a1, void *a2, void *a3, void *a4, int alg,
                         int seq, int status, void *a8, void *a9, unsigned char a10);
long __wrap_wlc_sendauth(void *a1, void *a2, void *a3, void *a4, int alg,
                         int seq, int status, void *a8, void *a9, unsigned char a10)
{
	/* Let the firmware's auth SEND proceed so it enters the authenticating state
	 * (needed for the RX dispatch to route the AP's auth reply to us). The stub it
	 * emits is harmless (AP rejects it); wpa_supplicant drives the real SAE in parallel. */
	long ret;

	if (alg == 3) {
		wl_sae.bsscfg = a1;     /* capture bsscfg for the post-SAE assoc drive */
		wl_sae.scb = a4;        /* capture AP scb (wlc_sendauth arg4) for host mgmt TX */
		/* arg2 is the destination (the AP) -- learn the BSSID here when .connect didn't get
		 * one (NetworkManager connects by SSID, no fixed BSSID). */
		if (a2 && !(wl_sae.bssid[0] | wl_sae.bssid[1] | wl_sae.bssid[2] |
		            wl_sae.bssid[3] | wl_sae.bssid[4] | wl_sae.bssid[5]))
			memcpy(wl_sae.bssid, a2, ETH_ALEN);
		re_log("re: firmware auth alg=3 seq=%d bssid=%pM bsscfg=%px scb=%px (passthrough)\n",
		       seq, wl_sae.bssid, a1, a4);
	}
	ret = wlc_sendauth(a1, a2, a3, a4, alg, seq, status, a8, a9, a10);
	if (alg == 3 && wl_sae.armed && wl_sae.inited && !wl_sae.stub_seen) {
		/* the stub is out: now (and only now) let wpa_supplicant start the real SAE exchange */
		wl_sae.stub_seen = true;
		mod_delayed_work(system_wq, &wl_sae.work, msecs_to_jiffies(WL_SAE_STUB_GRACE_MS));
	}
	return ret;
}

extern void wlc_authresp_client(void *bsscfg, long p2, unsigned short *body,
                                unsigned int len, unsigned char p5);
void __wrap_wlc_authresp_client(void *bsscfg, long p2, unsigned short *body,
                                unsigned int len, unsigned char p5)
{
	unsigned int alg = body ? body[0] : 0;
	unsigned int st  = (body && len >= 6) ? body[2] : 0xffff;
	re_log("re: AUTHRESP_WRAP ENTER alg=%u seq=%u st=%u len=%u\n",
	       alg, body ? body[1] : 0xffff, st, len);
	if (alg == 3) {
		/* SAE auth frames are forwarded to wpa_supplicant by __wrap_wlc_recv (the
		 * primary RX hook). Here we ONLY suppress the SAE-ignorant firmware handler;
		 * do NOT re-forward (the old double cfg80211_rx_mgmt under WL_LOCK hard-locked
		 * the kernel on the confirm frame). Pure drop. */
		(void)st;
		return;
	}
	wlc_authresp_client(bsscfg, p2, body, len, p5);
}

/* ===== SW CCMP for 802.11w robust management frames (SA-Query) =====
 * The blob decrypts DATA with the PTK but never MGMT frames, so the AP's protected SA-Query
 * arrives as ciphertext. We capture the TK and do AES-CCM (CCMP) in software to read the
 * SA-Query Request and emit a protected SA-Query Response, defeating the SA-Query teardown. */
#include <crypto/aead.h>
#include <linux/scatterlist.h>

/* CCMP nonce(13) + AAD(22) for non-QoS 3-addr mgmt header h; pn[0..5] = PN0..PN5. */
static void wl_re_ccmp_blocks(const u8 *h, const u8 *pn, u8 *nonce, u8 *aad)
{
	u16 fc = h[0] | (h[1] << 8);
	u16 seq;
	nonce[0] = 0x10;                 /* flags: management frame, priority 0 */
	memcpy(nonce + 1, h + 10, 6);    /* A2 */
	nonce[7] = pn[5]; nonce[8] = pn[4]; nonce[9] = pn[3];
	nonce[10] = pn[2]; nonce[11] = pn[1]; nonce[12] = pn[0];
	fc = (fc & ~0x3800) | 0x4000;    /* clear retry/pwrmgmt/moredata; protected set */
	aad[0] = fc & 0xff; aad[1] = fc >> 8;
	memcpy(aad + 2, h + 4, 18);      /* A1 A2 A3 */
	seq = (h[22] | (h[23] << 8)) & 0x000f;
	aad[20] = seq & 0xff; aad[21] = seq >> 8;
}

static struct crypto_aead *wl_saq_tfm;   /* cached AES-CCM tfm (alloc once; serialized use) */
static DEFINE_MUTEX(wl_saq_lock);        /* tfm + its key are shared by the SA-Query worker and the deauth */

/* Lazily allocate the AES-CCM tfm once (process context) and key it with the current TK (cheap, done
 * per call). Caller holds wl_saq_lock. */
static int wl_re_ccm_setup(void)
{
	if (!wl_saq_tfm) {
		wl_saq_tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(wl_saq_tfm)) {
			wl_saq_tfm = NULL;
			return -ENOMEM;
		}
		crypto_aead_setauthsize(wl_saq_tfm, 8);
	}
	return crypto_aead_setkey(wl_saq_tfm, wl_sae.tk, 16);
}

/* in-place AES-CCM over a fresh [aad||data] buffer using a pre-keyed tfm.
 * enc: data=pt(dlen) -> ct(dlen)+MIC(8). dec: data=ct(dlen)+MIC(8) -> pt(dlen). 0 on success. */
static int wl_re_ccm_with(struct crypto_aead *tfm, gfp_t gfp, bool enc, const u8 *nonce, const u8 *aad,
                          unsigned aadlen, u8 *data, unsigned dlen)
{
	struct aead_request *req; struct scatterlist sg;
	u8 iv[16]; u8 *buf; int ret = -1; unsigned cl = dlen + 8;
	if (!tfm)
		return -1;
	req = aead_request_alloc(tfm, gfp);
	if (!req) return -1;
	iv[0] = 1; memcpy(iv + 1, nonce, 13); iv[14] = 0; iv[15] = 0;
	buf = kmalloc(aadlen + cl, gfp);
	if (!buf) goto out_req;
	memcpy(buf, aad, aadlen);
	memcpy(buf + aadlen, data, enc ? dlen : cl);
	sg_init_one(&sg, buf, aadlen + cl);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, aadlen);
	aead_request_set_crypt(req, &sg, &sg, enc ? dlen : cl, iv);
	ret = enc ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req);
	if (ret == 0)
		memcpy(data, buf + aadlen, enc ? cl : dlen);
	kfree(buf);
out_req:
	aead_request_free(req);
	return ret;
}

static int wl_re_ccm(bool enc, const u8 *nonce, const u8 *aad, unsigned aadlen, u8 *data, unsigned dlen)
{
	return wl_re_ccm_with(wl_saq_tfm, GFP_KERNEL, enc, nonce, aad, aadlen, data, dlen);
}

/* ===== Block Ack (ADDBA/DELBA) through PMF =====
 * With 802.11w the AP protects its Block-Ack action frames (robust category 3), which the blob
 * cannot decrypt, and the AP drops the blob's own unprotected ones. Without a Block-Ack agreement
 * there is no frame aggregation and the AP keeps re-sending its ADDBA Request (seen: 14 Mbit/s
 * instead of ~190). These frames are handled in the blob's RX/TX context (atomic), so they need a
 * synchronous AES-CCM tfm of their own, used under a spinlock.
 *   re_pmf_ba = 0: off (old behaviour), 1: decline the AP's ADDBA (protected response, no aggregation),
 *               2: decrypt the AP's Block-Ack frames for the blob and protect the blob's ones.
 *   re_ba_rxclr: RxStatus1 bits to clear in the rx header of a re-injected frame (diagnostic). */
int re_pmf_ba = 2;
module_param(re_pmf_ba, int, 0644);
MODULE_PARM_DESC(re_pmf_ba, "802.11w Block Ack: 0=off, 1=decline the AP's ADDBA, 2=full (default)");
int re_pmf_stall = 1;
module_param(re_pmf_stall, int, 0644);
MODULE_PARM_DESC(re_pmf_stall, "PMF link with most frames retried for 12 s: 0=off, 1=probe the AP only (default), 2=also drop the link after 3 such windows, 3=test mode (every window counts as bad, drops)");
unsigned int re_ba_rxclr;
module_param(re_ba_rxclr, uint, 0644);
MODULE_PARM_DESC(re_ba_rxclr, "debug: RxStatus1 bits to clear on re-injected Block-Ack frames");

static struct crypto_aead *wl_re_fast_tfm;
static DEFINE_SPINLOCK(wl_re_fast_lock);
static bool wl_re_fast_ok;

static void wl_re_fast_key(const u8 *tk)
{
	unsigned long fl;

	if (!wl_re_fast_tfm) {
		struct crypto_aead *t = crypto_alloc_aead("ccm(aes)", 0, CRYPTO_ALG_ASYNC);

		if (IS_ERR(t)) {
			re_log("re ba: no synchronous ccm(aes) (%ld) -> Block Ack under PMF disabled\n", PTR_ERR(t));
			return;
		}
		crypto_aead_setauthsize(t, 8);
		wl_re_fast_tfm = t;
	}
	spin_lock_irqsave(&wl_re_fast_lock, fl);
	wl_re_fast_ok = crypto_aead_setkey(wl_re_fast_tfm, tk, 16) == 0;
	spin_unlock_irqrestore(&wl_re_fast_lock, fl);
}

static void wl_re_crypto_exit(void)
{
	unsigned long fl;
	struct crypto_aead *t;

	spin_lock_irqsave(&wl_re_fast_lock, fl);
	wl_re_fast_ok = false;
	t = wl_re_fast_tfm;
	wl_re_fast_tfm = NULL;
	spin_unlock_irqrestore(&wl_re_fast_lock, fl);
	if (t)
		crypto_free_aead(t);
	if (wl_saq_tfm) {
		crypto_free_aead(wl_saq_tfm);
		wl_saq_tfm = NULL;
	}
}

/* atomic-context AES-CCM with the synchronous tfm; dlen <= 48 */
static int wl_re_ccm_fast(bool enc, const u8 *nonce, const u8 *aad, u8 *data, unsigned dlen)
{
	unsigned long fl;
	int ret;

	if (dlen > 48)
		return -EMSGSIZE;
	spin_lock_irqsave(&wl_re_fast_lock, fl);
	ret = wl_re_fast_ok ? wl_re_ccm_with(wl_re_fast_tfm, GFP_ATOMIC, enc, nonce, aad, 22, data, dlen) : -ENOKEY;
	spin_unlock_irqrestore(&wl_re_fast_lock, fl);
	return ret;
}

static inline u64 wl_re_ccmp_pn(const u8 *p)   /* PN from the 8-byte CCMP header */
{
	return (u64)p[0] | (u64)p[1] << 8 | (u64)p[4] << 16 | (u64)p[5] << 24 | (u64)p[6] << 32 | (u64)p[7] << 40;
}

/* RX, atomic context. skb->data + q = protected action frame from the AP (24B header, CCMP header,
 * ciphertext, MIC, FCS). Returns 1 if it was a Block-Ack frame and the skb now holds the same frame
 * unprotected and in plaintext (hand it to the blob), -1 to drop it, 0 if it is not for us. */
static int wl_re_ba_rx(struct sk_buff *skb, unsigned int q)
{
	u8 *p = skb->data + q;
	unsigned int flen = skb->len - q;
	u8 nonce[13], aad[22], pn[6], pt[56];
	int ctlen = (int)flen - 4 - 24 - 8 - 8;
	u64 pn64;

	if (re_pmf_ba < 2 || !wl_sae.tk_set || ctlen < 4 || ctlen > 48 || !(p[27] & 0x20) ||
	    memcmp(p + 16, wl_sae.bssid, 6) != 0)
		return 0;
	pn[0] = p[24]; pn[1] = p[25]; pn[2] = p[28]; pn[3] = p[29]; pn[4] = p[30]; pn[5] = p[31];
	wl_re_ccmp_blocks(p, pn, nonce, aad);
	memcpy(pt, p + 32, ctlen + 8);
	if (wl_re_ccm_fast(false, nonce, aad, pt, ctlen) != 0 || pt[0] != 3)
		return 0;                       /* not decryptable here, or not Block Ack: SA-Query path */
	pn64 = wl_re_ccmp_pn(p + 24);
	if (pn64 <= wl_sae.rx_ba_pn) {
		re_log("re ba: replayed protected BA frame pn=%llu <= %llu -> dropped\n",
		       (unsigned long long)pn64, (unsigned long long)wl_sae.rx_ba_pn);
		return -1;
	}
	wl_sae.rx_ba_pn = pn64;
	if (re_verbose) {
		u16 st = q >= 6 ? skb->data[4] | (skb->data[5] << 8) : 0;

		re_log("re ba: AP %s token=%02x rxstatus1=0x%04x -> blob\n",
		       pt[1] == 0 ? "ADDBA req" : pt[1] == 1 ? "ADDBA resp" : pt[1] == 2 ? "DELBA" : "BA action",
		       pt[2], st);
	}
	memcpy(p + 24, pt, ctlen);
	memmove(p + 24 + ctlen, p + flen - 4, 4);       /* keep the FCS bytes */
	p[1] &= ~0x40;                                  /* no longer protected */
	skb_trim(skb, q + 24 + ctlen + 4);
	if (re_ba_rxclr && q >= 6) {
		u16 st = skb->data[4] | (skb->data[5] << 8);

		st &= ~(u16)re_ba_rxclr;
		skb->data[4] = st & 0xff;
		skb->data[5] = st >> 8;
	}
	return 1;
}

/* TX, atomic context, from the blob's wlc_sendmgmt(): protect the blob's own Block-Ack action
 * frame (ADDBA req/resp, DELBA) to the AP in place, like the AP does under PMF. */
static void wl_re_ba_tx(struct sk_buff *skb)
{
	u8 nonce[13], aad[22], pn[6], pt[24];
	unsigned int q, lim, blen;
	u64 txpn;
	u8 *p;

	if (!skb || !wl_sae.dev || skb->len < 24 + 6 || skb->len > 160)
		return;
	lim = skb->len - (24 + 6);
	if (lim > 64)
		lim = 64;
	for (q = 0; q <= lim; q++) {
		p = skb->data + q;
		if (p[0] == 0xd0 && !(p[1] & 0x40) && p[24] == 3 &&
		    memcmp(p + 4, wl_sae.bssid, 6) == 0 &&
		    memcmp(p + 10, wl_sae.dev->dev_addr, 6) == 0 &&
		    memcmp(p + 16, wl_sae.bssid, 6) == 0)
			break;
	}
	if (q > lim)
		return;
	blen = skb->len - q - 24;
	if (blen < 4 || blen > 16)
		return;
	if (skb_tailroom(skb) < 16 && pskb_expand_head(skb, 0, 16, GFP_ATOMIC)) {
		re_log("re ba: no tailroom for the CCMP MIC, frame sent unprotected\n");
		return;
	}
	p = skb->data + q;
	txpn = (u64)atomic64_fetch_inc(&wl_sae.tx_pn);
	pn[0] = txpn & 0xff; pn[1] = (txpn >> 8) & 0xff; pn[2] = (txpn >> 16) & 0xff;
	pn[3] = (txpn >> 24) & 0xff; pn[4] = (txpn >> 32) & 0xff; pn[5] = (txpn >> 40) & 0xff;
	wl_re_ccmp_blocks(p, pn, nonce, aad);
	memcpy(pt, p + 24, blen);
	if (wl_re_ccm_fast(true, nonce, aad, pt, blen) != 0) {
		re_log("re ba: CCMP encrypt failed, frame sent unprotected\n");
		return;
	}
	re_log("re ba: protecting the blob's BA action act=%u len=%u pn=%llu\n",
	       p[25], blen, (unsigned long long)txpn);
	p[1] |= 0x40;                                   /* Protected Frame */
	p[24] = pn[0]; p[25] = pn[1]; p[26] = 0; p[27] = 0x20;   /* CCMP header, key id 0 */
	p[28] = pn[2]; p[29] = pn[3]; p[30] = pn[4]; p[31] = pn[5];
	memcpy(p + 32, pt, blen + 8);
	skb_put(skb, 16);
}

extern int wlc_sendmgmt(void *wlc, void *pkt, void *txq, void *scb, long a5, long a6);
int __wrap_wlc_sendmgmt(void *wlc, void *pkt, void *txq, void *scb, long a5, long a6)
{
	if (re_pmf_ba >= 2 && wl_sae.pmf_active && wl_sae.tk_set)
		wl_re_ba_tx((struct sk_buff *)pkt);
	return wlc_sendmgmt(wlc, pkt, txq, scb, a5, a6);
}

/* Deferred (process-context) handler: SW-decrypt the captured protected action frame; if it is
 * an SA-Query Request, build + SW-encrypt + TX a protected SA-Query Response. */
extern int wl_re_mgmt_tx(struct net_device *dev, const unsigned char *f, int flen, void *scb);
extern void *wl_re_find_scb(struct net_device *dev, const unsigned char *mac);
static int wl_re_tx_prot_locked(struct net_device *dev, u8 fc0, const u8 *body, unsigned int blen);
static void wl_re_saq_work(struct work_struct *w)
{
	u8 *f = wl_sae.saq_frame;
	unsigned int flen = wl_sae.saq_len;
	u8 nonce[13], aad[22], pn[6], body[72];
	int ctlen;
	bool locked = false;

	if (!wl_sae.tk_set || !wl_sae.dev || flen < 24 + 8 + 8 + 4 + 4)
		goto done;
	mutex_lock(&wl_saq_lock);
	locked = true;
	if (wl_re_ccm_setup())
		goto done;
	ctlen = (int)flen - 4 /*FCS*/ - 24 - 8 - 8;
	if (ctlen <= 0 || ctlen > 60)
		goto done;
	pn[0] = f[24]; pn[1] = f[25]; pn[2] = f[28];
	pn[3] = f[29]; pn[4] = f[30]; pn[5] = f[31];
	wl_re_ccmp_blocks(f, pn, nonce, aad);
	memcpy(body, f + 32, ctlen + 8);   /* ct + MIC */
	if (wl_re_ccm(false, nonce, aad, 22, body, ctlen) != 0) {
		re_log("re saq: CCMP decrypt FAILED (ctlen=%d)\n", ctlen);
		goto done;
	}
	re_log("re saq: decrypted action cat=%u act=%u transid=%02x%02x ctlen=%d\n",
	       body[0], body[1], ctlen >= 4 ? body[2] : 0, ctlen >= 4 ? body[3] : 0, ctlen);
	if (ctlen >= 4 && body[0] == 8 && body[1] == 1) {   /* SA-Query Response to our request */
		u16 tid = body[2] | (body[3] << 8);
		if (wl_sae.saq_pending && tid == wl_sae.saq_tid) {
			wl_sae.saq_pending = false;
			cancel_delayed_work(&wl_sae.saq_chk);
			re_log("re: SA-Query response tid=%04x -> association is alive\n", tid);
		}
	}
	if (re_pmf_ba >= 1 && ctlen >= 9 && body[0] == 3 && body[1] == 0) {   /* ADDBA Request we can't serve */
		/* The blob cannot take part in a protected Block-Ack setup (or re_pmf_ba=1): decline it
		 * properly instead of leaving the AP to re-send the request for ever. */
		u8 resp[9] = { 3, 1, body[2], WLAN_STATUS_REQUEST_DECLINED & 0xff, 0, body[3], body[4], 0, 0 };
		int rc = wl_re_tx_prot_locked(wl_sae.dev, 0xd0, resp, sizeof(resp));

		re_log("re ba: declined the AP's ADDBA Request token=%02x -> %d\n", body[2], rc);
	}
	if (ctlen >= 4 && body[0] == 8 && body[1] == 0) {   /* SA-Query Request */
		u8 rh[24], pt[12], resp[44];
		u8 rnonce[13], raad[22], rpn[6];
		u64 txpn = (u64)atomic64_fetch_inc(&wl_sae.tx_pn);
		int rc;
		void *scb;
		rh[0] = 0xd0; rh[1] = 0x40; rh[2] = 0; rh[3] = 0;   /* action + protected */
		memcpy(rh + 4, wl_sae.bssid, 6);            /* A1 = AP */
		memcpy(rh + 10, wl_sae.dev->dev_addr, 6);   /* A2 = us */
		memcpy(rh + 16, wl_sae.bssid, 6);           /* A3 = AP */
		rh[22] = 0; rh[23] = 0;
		rpn[0] = txpn & 0xff; rpn[1] = (txpn >> 8) & 0xff; rpn[2] = (txpn >> 16) & 0xff;
		rpn[3] = (txpn >> 24) & 0xff; rpn[4] = (txpn >> 32) & 0xff; rpn[5] = (txpn >> 40) & 0xff;
		wl_re_ccmp_blocks(rh, rpn, rnonce, raad);
		pt[0] = 8; pt[1] = 1; pt[2] = body[2]; pt[3] = body[3];   /* cat8 action1 transid */
		if (wl_re_ccm(true, rnonce, raad, 22, pt, 4) != 0) {
			re_log("re saq: CCMP encrypt FAILED\n");
			goto done;
		}
		memcpy(resp, rh, 24);
		resp[24] = rpn[0]; resp[25] = rpn[1]; resp[26] = 0; resp[27] = 0x20;  /* CCMP hdr keyid0 */
		resp[28] = rpn[2]; resp[29] = rpn[3]; resp[30] = rpn[4]; resp[31] = rpn[5];
		memcpy(resp + 32, pt, 12);   /* ct(4) + MIC(8) */
		scb = wl_re_find_scb(wl_sae.dev, wl_sae.bssid);   /* fresh scb (survives reconnect) */
		rc = wl_re_mgmt_tx(wl_sae.dev, resp, 44, scb);
		re_log("re saq: SENT SA-Query Response transid=%02x%02x pn=%llu -> %d\n",
		       body[2], body[3], (unsigned long long)txpn, rc);
	}
done:
	if (locked)
		mutex_unlock(&wl_saq_lock);
	wl_sae.saq_busy = false;
}

/* Build + TX a CCMP-protected robust management frame to the AP (process context only; caller holds
 * wl_saq_lock and has run wl_re_ccm_setup()). fc0 = frame control byte 0 (0xc0 deauth, 0xa0 disassoc,
 * 0xd0 action); body <= 16 bytes. */
static int wl_re_tx_prot_locked(struct net_device *dev, u8 fc0, const u8 *body, unsigned int blen)
{
	u8 rh[24], pt[16 + 8], frame[24 + 8 + 16 + 8];
	u8 nonce[13], aad[22], pn[6];
	u64 txpn;
	void *scb;
	int rc;

	txpn = (u64)atomic64_fetch_inc(&wl_sae.tx_pn);
	rh[0] = fc0; rh[1] = 0x40; rh[2] = 0; rh[3] = 0;    /* Protected Frame */
	memcpy(rh + 4, wl_sae.bssid, 6);                    /* A1 = AP */
	memcpy(rh + 10, dev->dev_addr, 6);                  /* A2 = us */
	memcpy(rh + 16, wl_sae.bssid, 6);                   /* A3 = AP */
	rh[22] = 0; rh[23] = 0;
	pn[0] = txpn & 0xff;         pn[1] = (txpn >> 8) & 0xff;  pn[2] = (txpn >> 16) & 0xff;
	pn[3] = (txpn >> 24) & 0xff; pn[4] = (txpn >> 32) & 0xff; pn[5] = (txpn >> 40) & 0xff;
	wl_re_ccmp_blocks(rh, pn, nonce, aad);
	memcpy(pt, body, blen);
	rc = wl_re_ccm(true, nonce, aad, 22, pt, blen);     /* -> blen bytes ciphertext + 8 bytes MIC */
	if (rc)
		return rc;
	memcpy(frame, rh, 24);
	frame[24] = pn[0]; frame[25] = pn[1]; frame[26] = 0; frame[27] = 0x20;   /* CCMP hdr, key 0 */
	frame[28] = pn[2]; frame[29] = pn[3]; frame[30] = pn[4]; frame[31] = pn[5];
	memcpy(frame + 32, pt, blen + 8);
	scb = wl_re_find_scb(dev, wl_sae.bssid);
	return scb ? wl_re_mgmt_tx(dev, frame, 24 + 8 + blen + 8, scb) : -ENOENT;
}

static int wl_re_send_protected_mgmt(struct net_device *dev, u8 fc0, const u8 *body, unsigned int blen)
{
	int rc;

	if (!wl_sae.tk_set || blen == 0 || blen > 16)
		return -ENOENT;
	mutex_lock(&wl_saq_lock);
	rc = wl_re_ccm_setup();
	if (!rc)
		rc = wl_re_tx_prot_locked(dev, fc0, body, blen);
	mutex_unlock(&wl_saq_lock);
	return rc;
}

static int wl_re_send_protected_deauth(struct net_device *dev, u16 reason)
{
	u8 b[2] = { reason & 0xff, reason >> 8 };

	return wl_re_send_protected_mgmt(dev, 0xc0, b, sizeof(b));
}

/* The AP no longer talks to us (or we could not confirm it still does): behave like a link-down
 * event so cfg80211/wpa_supplicant reconnect. Process context. */
static void wl_re_assoc_lost(struct net_device *dev, u16 reason, const char *why)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	scb_val_t scbval;

	if (!test_bit(WL_STATUS_CONNECTED, &wl->status)) {
		re_log("re: assoc lost (%s) but already disconnected\n", why);
		return;
	}
	re_log("re: association lost (%s, reason %u) -> disconnecting\n", why, reason);
	wl_sae.saq_pending = false;
	wl_sae.sae_ok = false;
	wl_sae.pmf_active = false;
	wl_sae.tk_set = false;
	memset(&scbval, 0, sizeof(scbval));
	memcpy(&scbval.ea, wl_sae.bssid, ETHER_ADDR_LEN);
	scbval.val = htod32(reason);
	wl_dev_ioctl(dev, WLC_DISASSOC, &scbval, sizeof(scbval));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
	cfg80211_disconnected(dev, reason, NULL, 0, GFP_KERNEL);
#else
	cfg80211_disconnected(dev, reason, NULL, 0, false, GFP_KERNEL);
#endif
	clear_bit(WL_STATUS_CONNECTED, &wl->status);
	wl_link_down(wl);
	wl_init_prof(wl->profile);
}

#define WL_SAQ_RETRY_MS		300
#define WL_SAQ_MAX_TRIES	3

static void wl_re_saq_send(struct net_device *dev)
{
	u8 body[4] = { 8, 0, wl_sae.saq_tid & 0xff, wl_sae.saq_tid >> 8 };   /* SA Query Request */
	int rc = wl_re_send_protected_mgmt(dev, 0xd0, body, sizeof(body));

	wl_sae.saq_tries++;
	re_log("re: SA-Query request #%d tid=%04x -> %d\n", wl_sae.saq_tries, wl_sae.saq_tid, rc);
}

/* Stalled-link detector, called once a second from the driver watchdog with the interface's frame
 * counters. A PMF link can go bad without any deauth we would notice: the blob's rate control runs
 * away to the top rate (1300 Mbit/s) after a scan, almost nothing we send is ACKed any more (about
 * one retry per frame or worse, while the frames from the AP still trickle in), and the stack keeps
 * showing "connected" (seen in soak tests: 90 s+ of dead link, no recovery without a manual
 * reconnect). Judge 12 s windows (not the ones with a scan in them: those always show a burst of
 * retries). A window with retries >= 70% of the frames sent makes us probe the AP with an SA Query:
 * silence drops the link. If the probe is answered but the link stays that bad for 3 windows in a
 * row, drop it anyway: a fresh association resets the blob's per-station state. */
#define WL_STALL_WINDOW_S	12
#define WL_STALL_MIN_RETRY	40
#define WL_STALL_PROBE_GAP_S	30
#define WL_STALL_FORCE_WINDOWS	3
void wl_re_link_tick(struct net_device *dev, unsigned long tx, unsigned long retry)
{
	static unsigned long w_tx, w_retry, scan_seen, last_probe;
	static unsigned int ticks, bad;
	struct wl_cfg80211_priv *wl;
	unsigned long dtx, dretry;

	if (!wl_sae.inited || dev != wl_sae.dev || !wl_sae.pmf_active || !wl_sae.tk_set || re_pmf_stall == 0) {
		ticks = 0; bad = 0;
		return;
	}
	wl = ndev_to_wl(dev);
	if (!test_bit(WL_STATUS_CONNECTED, &wl->status)) {
		ticks = 0; bad = 0;
		return;
	}
	if (wl->scan_request)
		scan_seen = jiffies;
	if (ticks == 0) {
		w_tx = tx;
		w_retry = retry;
	}
	if (++ticks < WL_STALL_WINDOW_S)
		return;
	ticks = 0;
	dtx = tx - w_tx;
	dretry = retry - w_retry;
	if (re_pmf_stall == 3)                 /* test mode: pretend every window is bad */
		dretry = WL_STALL_MIN_RETRY + 2 * dtx;
	else if (time_before(jiffies, scan_seen + (WL_STALL_WINDOW_S + 3) * HZ)) {
		bad = 0;                       /* a scan always costs a burst of retries */
		return;
	}
	if (dretry < WL_STALL_MIN_RETRY || dretry * 10 < dtx * 7) {
		bad = 0;
		return;
	}
	bad++;
	re_log("re: link stall? %lu retries for %lu frames in %d s (window %u)\n",
	       dretry, dtx, WL_STALL_WINDOW_S, bad);
	if (wl_sae.dd_busy || wl_sae.saq_pending)
		return;
	if (bad >= WL_STALL_FORCE_WINDOWS && re_pmf_stall >= 2) {
		bad = 0;
		wl_sae.dd_kind = 2;            /* drop the link */
	} else if (bad < WL_STALL_FORCE_WINDOWS && time_after(jiffies, last_probe + WL_STALL_PROBE_GAP_S * HZ)) {
		last_probe = jiffies;
		wl_sae.dd_kind = 1;            /* SA Query */
	} else {
		return;
	}
	wl_sae.dd_busy = true;
	schedule_work(&wl_sae.dd_work);
}

/* 802.11w 11.13: an unprotected "class 2/3" deauth must not be obeyed, but the association has to be
 * verified. Ask the AP; a valid protected response means it is alive (ignore the frame), silence
 * means it dropped us and we must reconnect. */
static void wl_re_saq_start(struct net_device *dev, const char *why)
{
	if (wl_sae.saq_pending || !wl_sae.tk_set || !wl_sae.pmf_active)
		return;
	get_random_bytes(&wl_sae.saq_tid, sizeof(wl_sae.saq_tid));
	wl_sae.saq_tries = 0;
	wl_sae.saq_pending = true;
	re_log("re: SA-Query started (%s)\n", why);
	wl_re_saq_send(dev);
	schedule_delayed_work(&wl_sae.saq_chk, msecs_to_jiffies(WL_SAQ_RETRY_MS));
}

static void wl_re_saq_chk_work(struct work_struct *w)
{
	struct net_device *dev = wl_sae.dev;

	if (!wl_sae.saq_pending)
		return;
	if (!dev || !wl_sae.pmf_active) {
		wl_sae.saq_pending = false;
		return;
	}
	if (wl_sae.saq_tries >= WL_SAQ_MAX_TRIES) {
		wl_sae.saq_pending = false;
		wl_re_assoc_lost(dev, WLAN_REASON_UNSPECIFIED, "no SA-Query response");
		return;
	}
	wl_re_saq_send(dev);
	schedule_delayed_work(&wl_sae.saq_chk, msecs_to_jiffies(WL_SAQ_RETRY_MS));
}

static void wl_re_dd_work(struct work_struct *w)
{
	struct net_device *dev = wl_sae.dev;
	u8 *f = wl_sae.dd_frame;
	unsigned int flen = wl_sae.dd_len;
	u8 nonce[13], aad[22], pn[6], buf[2 + 8];
	u64 pn64;
	bool locked = false;
	u16 reason;

	if (!dev || !wl_sae.pmf_active)
		goto done;
	if (wl_sae.dd_kind == 1) {
		wl_re_saq_start(dev, "link check (after resume / retries)");
		goto done;
	}
	if (wl_sae.dd_kind == 2) {
		wl_re_assoc_lost(dev, WLAN_REASON_UNSPECIFIED, "most transmissions fail, link unusable");
		goto done;
	}
	if (flen < 26)
		goto done;
	if (!wl_sae.dd_prot) {
		reason = f[24] | (f[25] << 8);
		if (reason == 6 || reason == 7)
			wl_re_saq_start(dev, "unprotected class 2/3 deauth");
		goto done;
	}
	/* protected deauth/disassoc: CCMP hdr(8) + reason(2) + MIC(8) after the 24-byte header */
	if (!wl_sae.tk_set || flen < 24 + 8 + 2 + 8)
		goto done;
	pn[0] = f[24]; pn[1] = f[25]; pn[2] = f[28]; pn[3] = f[29]; pn[4] = f[30]; pn[5] = f[31];
	pn64 = (u64)pn[0] | ((u64)pn[1] << 8) | ((u64)pn[2] << 16) | ((u64)pn[3] << 24) |
	       ((u64)pn[4] << 32) | ((u64)pn[5] << 40);
	if (pn64 <= wl_sae.rx_mgmt_pn) {
		re_log("re: protected deauth/disassoc replayed (pn %llu <= %llu) -> ignored\n",
		       (unsigned long long)pn64, (unsigned long long)wl_sae.rx_mgmt_pn);
		goto done;
	}
	mutex_lock(&wl_saq_lock);
	locked = true;
	if (wl_re_ccm_setup())
		goto done;
	wl_re_ccmp_blocks(f, pn, nonce, aad);
	memcpy(buf, f + 32, 2 + 8);
	if (wl_re_ccm(false, nonce, aad, 22, buf, 2) != 0) {
		re_log("re: protected deauth/disassoc: CCMP verify FAILED -> ignored\n");
		goto done;
	}
	wl_sae.rx_mgmt_pn = pn64;
	reason = buf[0] | (buf[1] << 8);
	mutex_unlock(&wl_saq_lock);
	locked = false;
	wl_re_assoc_lost(dev, reason, f[0] == 0xc0 ? "protected deauth from AP" : "protected disassoc from AP");
done:
	if (locked)
		mutex_unlock(&wl_saq_lock);
	wl_sae.dd_busy = false;
}
/* ===== end SW CCMP / SA-Query ===== */

/* Tap the per-frame RX entry (before the firmware's auth-state matching drops frames for
 * transactions it doesn't own) and forward received SAE auth frames to wpa_supplicant.
 * At wlc_recv entry skb->data points at the d11 rx-header; the 802.11 frame follows at
 * rxoff = *(u32*)(wlc+0x6bc) (+2 if the pad flag rxhdr[0x10]&4 is set). */
extern void wlc_recv(void *wlc, void *pkt);
extern void wl_re_pktfree(struct net_device *dev, void *pkt);
void __wrap_wlc_recv(void *wlc, void *pkt)
{
	struct sk_buff *skb = (struct sk_buff *)pkt;
	if (wl_sae.armed && wl_sae.dev && skb && skb->len > 60 && skb->len < 4096) {
		const unsigned char *me = wl_sae.dev->dev_addr;
		unsigned int q, lim = skb->len - 30;
		if (lim > 112)
			lim = 112;
		/* locate an 802.11 Authentication frame addressed to us: FC=0xb0, addr1=our MAC */
		for (q = 0; q < lim; q++) {
			if (skb->data[q] == 0xb0 && memcmp(skb->data + q + 4, me, 6) == 0) {
				const unsigned char *f = skb->data + q;
				unsigned int flen = skb->len - q;
				unsigned int algv = f[24] | (f[25] << 8);
				unsigned int stv  = f[28] | (f[29] << 8);
				if (flen > 28)
					flen -= 4;          /* drop trailing FCS */
				re_log("re: RX AUTH @%u alg=%u seq=%u status=%u flen=%u%s\n",
				       q, algv, f[26] | (f[27] << 8), stv, flen,
				       algv == 3 ? " (consume)" : "");
				if (algv == 3) {
					/* SAE auth frame: forward valid (status==0) ones to wpa_supplicant,
					 * then CONSUME the pkt -- do NOT hand it to the firmware's wlc_recv.
					 * Letting the blob process SAE auth frames runs its auth FSM + a deep
					 * glue->blob->glue wrapped-call nest (across unpatched return thunks)
					 * that hard-locks the kernel on the confirm frame. Keeping the blob
					 * entirely out of the SAE auth exchange is the clean architecture. */
					if (stv == 0 && wl_sae.dev->ieee80211_ptr) {
						bool ok = cfg80211_rx_mgmt(wl_sae.dev->ieee80211_ptr,
						                           wl_sae.freq ? wl_sae.freq : 2447, 0, f, flen, 0);
						re_log("re: forwarded SAE frame -> userspace, delivered=%d\n", ok);
					}
					wl_re_pktfree(wl_sae.dev, pkt);   /* free RX skb ourselves */
					return;                           /* consumed: skip blob wlc_recv */
				}
				break;
			}
		}
	}
	/* SW 802.11w PMF: once MFP is active, an unprotected robust management frame
	 * (deauth/disassoc) must be ignored -- this blocks the classic spoofed-deauth attack
	 * that the SAE-ignorant blob would otherwise honor. Anchor on FC subtype + SA/BSSID == AP
	 * and DA == us|mcast to avoid false positives, then drop if the Protected-Frame bit is clear. */
	if (wl_sae.pmf_active && wl_sae.dev && skb && skb->len > 28 && skb->len < 4096) {
		const unsigned char *me = wl_sae.dev->dev_addr;
		const unsigned char *ap = wl_sae.bssid;
		unsigned int q, lim = skb->len - 24;
		if (lim > 112)
			lim = 112;
		for (q = 0; q < lim; q++) {
			unsigned char fc0 = skb->data[q], fc1 = skb->data[q + 1];
			if ((fc0 == 0xc0 || fc0 == 0xa0) &&                       /* deauth / disassoc */
			    memcmp(skb->data + q + 10, ap, 6) == 0 &&             /* SA  = AP */
			    memcmp(skb->data + q + 16, ap, 6) == 0 &&             /* BSSID = AP */
			    (memcmp(skb->data + q + 4, me, 6) == 0 ||
			     (skb->data[q + 4] & 1))) {                           /* DA = us or mcast */
				if ((fc1 & 0x40) == 0) {                             /* Protected-Frame bit clear */
					unsigned int fl = skb->len - q;
					unsigned int rsn = q + 26 <= skb->len ? skb->data[q + 24] | (skb->data[q + 25] << 8) : 0;
					re_log("re pmf: DROP unprotected %s from AP, reason %u (spoofed-deauth defense)\n",
					       fc0 == 0xc0 ? "deauth" : "disassoc", rsn);
					/* "Class 2/3 frame from non-associated STA" (6/7) is what the AP sends when
					 * it no longer knows us. 802.11w: don't obey it, but check with an SA Query. */
					if ((rsn == 6 || rsn == 7) && !wl_sae.dd_busy && fl <= sizeof(wl_sae.dd_frame)) {
						memcpy(wl_sae.dd_frame, skb->data + q, fl);
						wl_sae.dd_len = fl;
						wl_sae.dd_prot = false;
						wl_sae.dd_kind = 0;
						wl_sae.dd_busy = true;
						schedule_work(&wl_sae.dd_work);
					}
					wl_re_pktfree(wl_sae.dev, pkt);
					return;
				}
				{
					unsigned int fl = skb->len - q;
					re_log("re pmf: PROTECTED %s from AP (len %u) -> verifying in software\n",
					       fc0 == 0xc0 ? "deauth" : "disassoc", fl);
					/* the blob cannot decrypt management frames: verify + honour it ourselves */
					if (!wl_sae.dd_busy && wl_sae.tk_set && fl <= sizeof(wl_sae.dd_frame)) {
						memcpy(wl_sae.dd_frame, skb->data + q, fl);
						wl_sae.dd_len = fl;
						wl_sae.dd_prot = true;
						wl_sae.dd_kind = 0;
						wl_sae.dd_busy = true;
						schedule_work(&wl_sae.dd_work);
					}
				}
				break;
			}
			/* A protected ACTION frame from the AP -> likely an 802.11w SA-Query Request the
			 * blob can't decrypt. Copy it out and hand to the deferred SW-CCMP responder
			 * (crypto can sleep; the RX path is atomic), then CONSUME it so the blob doesn't
			 * answer with an action-error. */
			if (fc0 == 0xd0 && (fc1 & 0x40) &&                        /* action, protected */
			    memcmp(skb->data + q + 10, ap, 6) == 0 &&             /* SA = AP */
			    memcmp(skb->data + q + 4, me, 6) == 0 &&              /* DA = us */
			    wl_sae.tk_set && re_pmf_ba >= 2) {
				/* Block Ack (ADDBA/DELBA): decrypt here and let the blob process it as if it had
				 * arrived unprotected, so a Block-Ack agreement (frame aggregation) can be set up. */
				int ba = wl_re_ba_rx(skb, q);

				if (ba > 0)
					goto pass;
				if (ba < 0) {
					wl_re_pktfree(wl_sae.dev, pkt);
					return;
				}
			}
			if (fc0 == 0xd0 && (fc1 & 0x40) &&                        /* action, protected */
			    memcmp(skb->data + q + 10, ap, 6) == 0 &&             /* SA = AP */
			    memcmp(skb->data + q + 4, me, 6) == 0 &&              /* DA = us */
			    wl_sae.tk_set && !wl_sae.saq_busy) {
				unsigned int fl = skb->len - q;
				if (fl <= sizeof(wl_sae.saq_frame)) {
					memcpy(wl_sae.saq_frame, skb->data + q, fl);
					wl_sae.saq_len = fl;
					wl_sae.saq_busy = true;
					schedule_work(&wl_sae.saq_work);
					re_log("re saq: queued protected action (len=%u) for SW decrypt\n", fl);
					wl_re_pktfree(wl_sae.dev, pkt);
					return;
				}
			}
		}
	}
pass:
	wlc_recv(wlc, pkt);
}
/* =================== end M3 bridge =================== */

static struct cfg80211_ops wl_cfg80211_ops = {
	.change_virtual_intf = wl_cfg80211_change_iface,
	.scan = wl_cfg80211_scan,
	.set_wiphy_params = wl_cfg80211_set_wiphy_params,
	.join_ibss = wl_cfg80211_join_ibss,
	.leave_ibss = wl_cfg80211_leave_ibss,
	.get_station = wl_cfg80211_get_station,
	.set_tx_power = wl_cfg80211_set_tx_power,
	.get_tx_power = wl_cfg80211_get_tx_power,
	.add_key = wl_cfg80211_add_key,
	.del_key = wl_cfg80211_del_key,
	.get_key = wl_cfg80211_get_key,
	.set_default_key = wl_cfg80211_config_default_key,
	.set_power_mgmt = wl_cfg80211_set_power_mgmt,
	.connect = wl_cfg80211_connect,
	.disconnect = wl_cfg80211_disconnect,
	.mgmt_tx = wl_cfg80211_mgmt_tx,
	.external_auth = wl_cfg80211_external_auth,
	.update_mgmt_frame_registrations = wl_cfg80211_update_mgmt_frame_registrations,
#ifdef CONFIG_PM
	.suspend = wl_cfg80211_suspend,
	.resume = wl_cfg80211_resume,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	.set_rekey_data = wl_cfg80211_rekey,
#endif 
#endif 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	.set_pmksa = wl_cfg80211_set_pmksa,
	.del_pmksa = wl_cfg80211_del_pmksa,
	.flush_pmksa = wl_cfg80211_flush_pmksa
#endif
};

#ifdef CONFIG_PM
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
static const struct wiphy_wowlan_support wl_wowlan_support = {
#else
static struct wiphy_wowlan_support wl_wowlan_support = {
#endif 
	.flags = WIPHY_WOWLAN_MAGIC_PKT
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	| WIPHY_WOWLAN_SUPPORTS_GTK_REKEY | WIPHY_WOWLAN_GTK_REKEY_FAILURE |
	WIPHY_WOWLAN_EAP_IDENTITY_REQ
#endif
	| WIPHY_WOWLAN_DISCONNECT,
};
#endif 
#endif 

static s32 wl_mode_to_nl80211_iftype(s32 mode)
{
	s32 err = 0;

	switch (mode) {
	case WL_MODE_BSS:
		return NL80211_IFTYPE_STATION;
	case WL_MODE_IBSS:
		return NL80211_IFTYPE_ADHOC;
	default:
		return NL80211_IFTYPE_UNSPECIFIED;
	}

	return err;
}

static s32 wl_alloc_wdev(struct device *dev, struct wireless_dev **rwdev)
{
	struct wireless_dev *wdev;
	s32 err = 0;

	wdev = kzalloc(sizeof(*wdev), GFP_KERNEL);
	if (!wdev) {
		WL_ERR(("Could not allocate wireless device\n"));
		err = -ENOMEM;
		goto early_out;
	}
	wdev->wiphy = wiphy_new(&wl_cfg80211_ops, sizeof(struct wl_cfg80211_priv));
	if (!wdev->wiphy) {
		WL_ERR(("Couldn not allocate wiphy device\n"));
		err = -ENOMEM;
		goto wiphy_new_out;
	}
	set_wiphy_dev(wdev->wiphy, dev);
	wdev->wiphy->max_scan_ssids = WL_NUM_SCAN_MAX;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	wdev->wiphy->max_num_pmkids = WL_NUM_PMKIDS_MAX;
#endif
	wdev->wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_ADHOC);
	wdev->wiphy->bands[NL80211_BAND_2GHZ] = &__wl_band_2ghz;
	wdev->wiphy->bands[NL80211_BAND_5GHZ] = &__wl_band_5ghz_a; 
	wdev->wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	wdev->wiphy->cipher_suites = __wl_cipher_suites;
	wdev->wiphy->n_cipher_suites = ARRAY_SIZE(__wl_cipher_suites);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	/* M2a: advertise SAE so wpa_supplicant issues a SAE .connect (auth_type=SAE,
	 * AKM=SAE), which our glue maps to auth=3 (G1) + accepts the AKM (G2) and the
	 * blob (P1) emits an alg=3 Authentication frame. We deliberately do NOT set
	 * NL80211_EXT_FEATURE_SAE_OFFLOAD (firmware can't do SAE) nor implement
	 * .external_auth yet -- this is purely to get the firmware to TX alg=3 for the
	 * M2a on-air conduit test. Full external-auth/PMK plumbing is M3. */
	wdev->wiphy->features |= NL80211_FEATURE_SAE;
	wdev->wiphy->mgmt_stypes = wl_cfg80211_txrx_stypes;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)

	wdev->wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;
#endif

#ifdef CONFIG_PM
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	wdev->wiphy->wowlan = &wl_wowlan_support;
#else
	wdev->wiphy->wowlan = wl_wowlan_support;
#endif 
#endif 
#endif 

	err = wiphy_register(wdev->wiphy);
	if (err < 0) {
		WL_ERR(("Couldn not register wiphy device (%d)\n", err));
		goto wiphy_register_out;
	}

	*rwdev = wdev;
	return err;

wiphy_register_out:
	wiphy_free(wdev->wiphy);

wiphy_new_out:
	kfree(wdev);

early_out:
	*rwdev = wdev;
	return err;
}

static void wl_free_wdev(struct wl_cfg80211_priv *wl)
{
	struct wireless_dev *wdev = wl_to_wdev(wl);

	if (!wdev) {
		WL_ERR(("wdev is invalid\n"));
		return;
	}
	wiphy_unregister(wdev->wiphy);
	wiphy_free(wdev->wiphy);
	kfree(wdev);
	wl_to_wdev(wl) = NULL;
}

static s32 wl_inform_bss(struct wl_cfg80211_priv *wl, struct wl_scan_results *bss_list)
{
	struct wl_bss_info *bi = NULL;	
	s32 err = 0;
	int i;

	if (bss_list->version != WL_BSS_INFO_VERSION) {
		WL_ERR(("Version %d != WL_BSS_INFO_VERSION\n", bss_list->version));
		return -EOPNOTSUPP;
	}
	WL_DBG(("scanned AP count (%d)\n", bss_list->count));
	bi = next_bss(bss_list, bi);
	for_each_bss(bss_list, bi, i) {
		err = wl_inform_single_bss(wl, bi);
		if (err)
			break;
	}
	return err;
}

static s32 wl_inform_single_bss(struct wl_cfg80211_priv *wl, struct wl_bss_info *bi)
{
	struct wiphy *wiphy = wl_to_wiphy(wl);
	struct ieee80211_mgmt *mgmt;
	struct ieee80211_channel *channel;
	struct wl_cfg80211_bss_info *notif_bss_info;
	struct wl_cfg80211_scan_req *sr = wl_to_sr(wl);
	struct beacon_proberesp *beacon_proberesp;
	struct cfg80211_bss *cbss = NULL;
	s32 mgmt_type;
	u32 signal;
	u32 freq;
	s32 err = 0;
	u8 *notify_ie;
	size_t notify_ielen;

	if (dtoh32(bi->length) > WL_BSS_INFO_MAX) {
		WL_DBG(("Beacon is larger than buffer. Discarding\n"));
		return -E2BIG;
	}
	notif_bss_info = kzalloc(sizeof(*notif_bss_info) + sizeof(*mgmt) - sizeof(u8) +
	                         WL_BSS_INFO_MAX, GFP_KERNEL);
	if (!notif_bss_info) {
		WL_ERR(("notif_bss_info alloc failed\n"));
		return -ENOMEM;
	}
	mgmt = (struct ieee80211_mgmt *)notif_bss_info->frame_buf;
	notif_bss_info->channel = bi->ctl_ch ? bi->ctl_ch : CHSPEC_CHANNEL(bi->chanspec);

	notif_bss_info->rssi = bi->RSSI;
	memcpy(mgmt->bssid, &bi->BSSID, ETHER_ADDR_LEN);
	mgmt_type = wl->active_scan ?	IEEE80211_STYPE_PROBE_RESP : IEEE80211_STYPE_BEACON;
	if (!memcmp(bi->SSID, sr->ssid.SSID, bi->SSID_len)) {
		mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | mgmt_type);
	}
	beacon_proberesp = wl->active_scan ? (struct beacon_proberesp *)&mgmt->u.probe_resp :
	                   (struct beacon_proberesp *)&mgmt->u.beacon;
	beacon_proberesp->timestamp = 0;
	beacon_proberesp->beacon_int = cpu_to_le16(bi->beacon_period);
	beacon_proberesp->capab_info = cpu_to_le16(bi->capability);
	wl_rst_ie(wl);

	err = wl_mrg_ie(wl, ((u8 *) bi) + bi->ie_offset, bi->ie_length);
	if (err)
		goto inform_single_bss_out;

	err = wl_cp_ie(wl, beacon_proberesp->variable, WL_BSS_INFO_MAX -
	         offsetof(struct wl_cfg80211_bss_info, frame_buf));
	if (err)
		goto inform_single_bss_out;

	notif_bss_info->frame_len = offsetof(struct ieee80211_mgmt, u.beacon.variable) +
	                            wl_get_ielen(wl);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	freq = ieee80211_channel_to_frequency(notif_bss_info->channel,
		(notif_bss_info->channel <= CH_MAX_2G_CHANNEL) ?
		NL80211_BAND_2GHZ : NL80211_BAND_5GHZ);
#else
	freq = ieee80211_channel_to_frequency(notif_bss_info->channel);
#endif
	if (freq == 0) {
		WL_ERR(("Invalid channel, fail to chcnage channel to freq\n"));
		err = -EINVAL;
		goto inform_single_bss_out;
	}
	channel = ieee80211_get_channel(wiphy, freq);
	if (unlikely(!channel)) {
		WL_ERR(("ieee80211_get_channel error\n"));
		err = -EINVAL;
		goto inform_single_bss_out;
	}

	WL_DBG(("SSID : \"%s\", rssi %d, channel %d, capability : 0x04%x, bssid %pM\n",
		bi->SSID, notif_bss_info->rssi, notif_bss_info->channel,
		mgmt->u.beacon.capab_info, &bi->BSSID));

	signal = notif_bss_info->rssi * 100;

	if (!wl->scan_request) {
		cbss = cfg80211_inform_bss_frame(wiphy, channel, mgmt,
			le16_to_cpu(notif_bss_info->frame_len), signal, GFP_KERNEL);
		if (unlikely(!cbss)) {
			WL_ERR(("cfg80211_inform_bss_frame error\n"));
			err = -ENOMEM;
			goto inform_single_bss_out;
		}
	} else {
		notify_ie = (u8 *)bi + le16_to_cpu(bi->ie_offset);
		notify_ielen = le32_to_cpu(bi->ie_length);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
		cbss = cfg80211_inform_bss(wiphy, channel, (const u8 *)(bi->BSSID.octet),
			0, beacon_proberesp->capab_info, beacon_proberesp->beacon_int,
			(const u8 *)notify_ie, notify_ielen, signal, GFP_KERNEL);
#else
		cbss = cfg80211_inform_bss(wiphy, channel,
				wl->active_scan ?
				CFG80211_BSS_FTYPE_PRESP : CFG80211_BSS_FTYPE_BEACON,
				(const u8 *)(bi->BSSID.octet), 0,
				beacon_proberesp->capab_info,
				beacon_proberesp->beacon_int,
				(const u8 *)notify_ie, notify_ielen, signal, GFP_KERNEL);
#endif
		if (unlikely(!cbss)) {
			WL_ERR(("cfg80211_inform_bss error\n"));
			err = -ENOMEM;
			goto inform_single_bss_out;
		}
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	cfg80211_put_bss(wiphy, cbss);
#else
	cfg80211_put_bss(cbss);
#endif

inform_single_bss_out:
	kfree(notif_bss_info);

	return err;
}

static s32
wl_notify_connect_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
                         const wl_event_msg_t *e, void *data)
{
	s32 err = 0;
	u32 event = EVENT_TYPE(e);
	u16 flags = EVENT_FLAGS(e);
	u32 status = EVENT_STATUS(e);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	struct ieee80211_channel *channel = NULL;
	struct wiphy *wiphy;
	u32 chanspec, chan;
	u32 freq, band;
#endif 

	re_log("re: ev connect_status event=%u status=%u flags=0x%x\n", event, status, flags);
	WL_DBG(("\n"));

	if (!wl_is_ibssmode(wl)) {
		if (event == WLC_E_LINK && (flags & WLC_EVENT_MSG_LINK)) {
			wl_link_up(wl);
			if (wl_bss_connect_done(wl, ndev, e, data, true) == -ECONNREFUSED) {
				wl_link_down(wl);   /* non-SAE join refused by the WPA3 guard */
				return 0;
			}
			wl->profile->active = true;
		}
		else if ((event == WLC_E_LINK && ~(flags & WLC_EVENT_MSG_LINK)) ||
			event == WLC_E_DEAUTH_IND || event == WLC_E_DISASSOC_IND) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
			cfg80211_disconnected(ndev, 0, NULL, 0, GFP_KERNEL);
#else
			cfg80211_disconnected(ndev, 0, NULL, 0, false, GFP_KERNEL);
#endif
			clear_bit(WL_STATUS_CONNECTED, &wl->status);
			wl_sae.sae_ok = false;   /* any (re)join must redo SAE */
			wl_sae.pmf_active = false;   /* no PMF session any more: stop filtering deauths */
			wl_sae.tk_set = false;
			wl_sae.saq_pending = false;
			wl_link_down(wl);
			wl_init_prof(wl->profile);
		}
		else if (event == WLC_E_SET_SSID && status != WLC_E_STATUS_SUCCESS) {
			/* Join failed (NO_NETWORKS, or FAIL e.g. the AP rejected the association right
			 * after a successful SAE): report it now instead of waiting for a timeout. */
			wl_sae.sae_ok = false;
			wl_bss_connect_done(wl, ndev, e, data, false);
		}
		else {
			WL_DBG(("no action (BSS mode)\n"));
		}
	}
	else {
		if (event == WLC_E_JOIN) {
			WL_DBG(("joined in IBSS network\n"));
		}
		if (event == WLC_E_START) {
			WL_DBG(("started IBSS network\n"));
		}
		if (event == WLC_E_JOIN || event == WLC_E_START) {
			wl_link_up(wl);
			wl_get_assoc_ies(wl);
			memcpy(&wl->bssid, &e->addr, ETHER_ADDR_LEN);
			wl_update_bss_info(wl);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
			wiphy = wl_to_wiphy(wl);
			err = wl_dev_intvar_get(ndev, "chanspec", &chanspec);
			if (err) {
				WL_ERR(("Could not get chanspec, err %d\n", err));
				return err;
			}
			chan = wf_chspec_ctlchan(chanspec);
			band = (chan <= CH_MAX_2G_CHANNEL) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
			freq = ieee80211_channel_to_frequency(chan, band);
			channel = ieee80211_get_channel(wiphy, freq);
			cfg80211_ibss_joined(ndev, (u8 *)&wl->bssid, channel, GFP_KERNEL);
#else
			cfg80211_ibss_joined(ndev, (u8 *)&wl->bssid, GFP_KERNEL);
#endif
			set_bit(WL_STATUS_CONNECTED, &wl->status);
			wl->profile->active = true;
		}
		else if ((event == WLC_E_LINK && ~(flags & WLC_EVENT_MSG_LINK)) ||
			event == WLC_E_DEAUTH_IND || event == WLC_E_DISASSOC_IND) {
			clear_bit(WL_STATUS_CONNECTED, &wl->status);
			wl_link_down(wl);
			wl_init_prof(wl->profile);
		}
		else if (event == WLC_E_SET_SSID && status == WLC_E_STATUS_NO_NETWORKS) {
			WL_DBG(("no action - join fail (IBSS mode)\n"));
		}
		else {
			WL_DBG(("no action (IBSS mode)\n"));
		}
	}

	return err;
}

static s32
wl_notify_roaming_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
                         const wl_event_msg_t *e, void *data)
{
	s32 err = 0;
	u32 status = EVENT_STATUS(e);

	re_log("re: ev roaming status=%u\n", status);

	if (status == WLC_E_STATUS_SUCCESS && wl_sae.sae_conn) {
		/* Firmware-initiated roam in an SAE connection: it re-associated with Open/PSK. Don't
		 * hand that to wpa_supplicant as a roam; drop the link so it reconnects with SAE. */
		scb_val_t scbval;
		re_log("re: firmware roam during SAE connection -> disconnecting\n");
		wl_sae.sae_ok = false;
		memset(&scbval, 0, sizeof(scbval));
		memcpy(&scbval.ea, &e->addr, ETHER_ADDR_LEN);
		scbval.val = htod32(WLAN_REASON_UNSPECIFIED);
		wl_dev_ioctl(ndev, WLC_DISASSOC, &scbval, sizeof(scbval));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
		cfg80211_disconnected(ndev, 0, NULL, 0, GFP_KERNEL);
#else
		cfg80211_disconnected(ndev, WLAN_REASON_UNSPECIFIED, NULL, 0, true, GFP_KERNEL);
#endif
		clear_bit(WL_STATUS_CONNECTED, &wl->status);
		wl_link_down(wl);
		wl_init_prof(wl->profile);
		return 0;
	}
	if (status == WLC_E_STATUS_SUCCESS) {
		err = wl_bss_roaming_done(wl, ndev, e, data);
		wl->profile->active = true;
	}

	return err;
}

static __used s32
wl_dev_bufvar_set(struct net_device *dev, s8 *name, s8 *buf, s32 len)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	u32 buflen;

	buflen = bcm_mkiovar(name, buf, len, wl->ioctl_buf, WL_IOCTL_LEN_MAX);
	BUG_ON(!buflen);

	return wl_dev_ioctl(dev, WLC_SET_VAR, wl->ioctl_buf, buflen);
}

static s32
wl_dev_bufvar_get(struct net_device *dev, s8 *name, s8 *buf, s32 buf_len)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(dev);
	u32 len;
	s32 err = 0;

	len = bcm_mkiovar(name, NULL, 0, wl->ioctl_buf, WL_IOCTL_LEN_MAX);
	BUG_ON(!len);
	err = wl_dev_ioctl(dev, WLC_GET_VAR, (void *)wl->ioctl_buf, WL_IOCTL_LEN_MAX);
	if (err) {
		WL_INF(("error (%d)\n", err));
		return err;
	}
	memcpy(buf, wl->ioctl_buf, buf_len);

	return err;
}

static s32 wl_get_assoc_ies(struct wl_cfg80211_priv *wl)
{
	struct net_device *ndev = wl_to_ndev(wl);
	struct wl_cfg80211_assoc_ielen *assoc_info;
	struct wl_cfg80211_connect_info *conn_info = wl_to_conn(wl);
	u32 req_len;
	u32 resp_len;
	s32 err = 0;

	err = wl_dev_bufvar_get(ndev, "assoc_info", wl->extra_buf, WL_ASSOC_INFO_MAX);
	if (err) {
		WL_ERR(("could not get assoc info (%d)\n", err));
		return err;
	}
	assoc_info = (struct wl_cfg80211_assoc_ielen *)wl->extra_buf;
	req_len = assoc_info->req_len;
	resp_len = assoc_info->resp_len;
	if (req_len) {
		err = wl_dev_bufvar_get(ndev, "assoc_req_ies", wl->extra_buf, WL_ASSOC_INFO_MAX);
		if (err) {
			WL_ERR(("could not get assoc req (%d)\n", err));
			return err;
		}
		conn_info->req_ie_len = req_len;
		conn_info->req_ie =
		    kmemdup(wl->extra_buf, conn_info->req_ie_len, GFP_KERNEL);
	} else {
		conn_info->req_ie_len = 0;
		conn_info->req_ie = NULL;
	}
	if (resp_len) {
		err = wl_dev_bufvar_get(ndev, "assoc_resp_ies", wl->extra_buf, WL_ASSOC_INFO_MAX);
		if (err) {
			WL_ERR(("could not get assoc resp (%d)\n", err));
			return err;
		}
		conn_info->resp_ie_len = resp_len;
		conn_info->resp_ie =
		    kmemdup(wl->extra_buf, conn_info->resp_ie_len, GFP_KERNEL);
	} else {
		conn_info->resp_ie_len = 0;
		conn_info->resp_ie = NULL;
	}
	WL_DBG(("req len (%d) resp len (%d)\n", conn_info->req_ie_len,
		conn_info->resp_ie_len));

	return err;
}

static void wl_ch_to_chanspec(struct ieee80211_channel *chan, struct wl_join_params *join_params,
	size_t *join_params_size)
{
	chanspec_t chanspec = 0;

	if (chan) {
		join_params->params.chanspec_num = 1;
		join_params->params.chanspec_list[0] =
		    ieee80211_frequency_to_channel(chan->center_freq);

		if ( (int) chan->band == (int) NL80211_BAND_2GHZ) {
			chanspec |= WL_CHANSPEC_BAND_2G;
		}
		else if ( (int) chan->band == (int) NL80211_BAND_5GHZ) {
			chanspec |= WL_CHANSPEC_BAND_5G;
		}
		else {
			WL_ERR(("Unknown band\n"));
			BUG();
		}

		chanspec |= WL_CHANSPEC_BW_20;

		*join_params_size += WL_ASSOC_PARAMS_FIXED_SIZE +
			join_params->params.chanspec_num * sizeof(chanspec_t);

		join_params->params.chanspec_list[0] &= WL_CHANSPEC_CHAN_MASK;
		join_params->params.chanspec_list[0] |= chanspec;
		join_params->params.chanspec_list[0] =
		    htodchanspec(join_params->params.chanspec_list[0]);

		join_params->params.chanspec_num = htod32(join_params->params.chanspec_num);

		WL_DBG(("join_params->params.chanspec_list[0]= %#X, channel %d, chanspec %#X\n",
		        join_params->params.chanspec_list[0],
		        join_params->params.chanspec_list[0], chanspec));
	}
}

/* cfg80211's entry for the AP we are associated to (NULL if it has none). The BSS-type/privacy
 * arguments changed in 4.1; the fallback lookup below used the pre-4.1 capability masks on every
 * kernel, which means "PBSS, privacy on" today and never matches an ESS BSS. */
static struct cfg80211_bss *wl_get_ess_bss(struct wl_cfg80211_priv *wl)
{
	struct wlc_ssid *ssid = &wl->profile->ssid;

	return cfg80211_get_bss(wl_to_wiphy(wl), NULL, (s8 *)&wl->bssid,
			       ssid->SSID, ssid->SSID_len,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
			       WLAN_CAPABILITY_ESS, WLAN_CAPABILITY_ESS
#else
			       IEEE80211_BSS_TYPE_ESS, IEEE80211_PRIVACY_ANY
#endif
			       );
}

static s32 wl_update_bss_info(struct wl_cfg80211_priv *wl)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	struct wiphy *wiphy = wl_to_wiphy(wl);
#endif
	struct cfg80211_bss *bss;
	struct wl_bss_info *bi;
	struct wlc_ssid *ssid;
	struct bcm_tlv *tim;
	s32 dtim_period;
	size_t ie_len;
	u8 *ie;
	s32 err = 0;

	ssid = &wl->profile->ssid;
	bss = wl_get_ess_bss(wl);

	rtnl_lock();
	if (!bss) {
		WL_DBG(("Could not find the AP\n"));
		*(u32 *) wl->extra_buf = htod32(WL_EXTRA_BUF_MAX);
		err = wl_dev_ioctl(wl_to_ndev(wl), WLC_GET_BSS_INFO, wl->extra_buf,
		                   WL_EXTRA_BUF_MAX);
		if (err) {
			WL_ERR(("Could not get bss info %d\n", err));
			goto update_bss_info_out;
		}
		bi = (struct wl_bss_info *)(wl->extra_buf + 4);
		if (memcmp(&bi->BSSID, &wl->bssid, ETHER_ADDR_LEN)) {
			err = -EIO;
			goto update_bss_info_out;
		}
		err = wl_inform_single_bss(wl, bi);
		if (err)
			goto update_bss_info_out;

		bss = wl_get_ess_bss(wl);

		ie = ((u8 *)bi) + bi->ie_offset;
		ie_len = bi->ie_length;
	} else {
		WL_DBG(("Found the AP in the list - BSSID %pM\n", bss->bssid));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
		ie = (u8 *)(bss->ies->data);
		ie_len = bss->ies->len;
#else
		ie = bss->information_elements;
		ie_len = bss->len_information_elements;
#endif
		wl->conf->channel = *bss->channel;
	}

	if (bss) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
		cfg80211_put_bss(wiphy, bss);
#else
		cfg80211_put_bss(bss);
#endif
	} else {
		WL_DBG(("Could not update BSS\n"));
		err = -EINVAL;
		goto update_bss_info_out;
	}

	tim = bcm_parse_tlvs(ie, ie_len, WLAN_EID_TIM);
	if (tim) {
		dtim_period = tim->data[1];
	} else {

		err = wl_dev_ioctl(wl_to_ndev(wl), WLC_GET_DTIMPRD,
			&dtim_period, sizeof(dtim_period));
		if (err) {
			WL_ERR(("WLC_GET_DTIMPRD error (%d)\n", err));
			goto update_bss_info_out;
		}
	}

update_bss_info_out:
	rtnl_unlock();
	return err;
}

static s32
wl_bss_roaming_done(struct wl_cfg80211_priv *wl, struct net_device *ndev,
                    const wl_event_msg_t *e, void *data)
{
	struct wl_cfg80211_connect_info *conn_info = wl_to_conn(wl);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct cfg80211_roam_info roam_info = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
		.bssid = wl->profile->bssid,
#else
		.links[0].bssid = wl->profile->bssid,
#endif
		.req_ie = conn_info->req_ie,
		.req_ie_len = conn_info->req_ie_len,
		.resp_ie = conn_info->resp_ie,
		.resp_ie_len = conn_info->resp_ie_len,
	};
#endif
	s32 err = 0;

	err = wl_get_assoc_ies(wl);
	if (err)
		return err;

	memcpy(wl->profile->bssid, &e->addr, ETHER_ADDR_LEN);
	memcpy(&wl->bssid, &e->addr, ETHER_ADDR_LEN);

	err = wl_update_bss_info(wl);
	if (err)
		return err;

	cfg80211_roamed(ndev,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
			&roam_info,
#else
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39)
			&wl->conf->channel,	 
#endif
			(u8 *)&wl->bssid,
			conn_info->req_ie, conn_info->req_ie_len,
			conn_info->resp_ie, conn_info->resp_ie_len,
#endif
			GFP_KERNEL);
	WL_DBG(("Report roaming result\n"));

	set_bit(WL_STATUS_CONNECTED, &wl->status);

	return err;
}

/* Abort an association we refuse to report as success: tear it down in the firmware and tell cfg80211
 * the connect failed so wpa_supplicant retries at once. */
static void wl_refuse_assoc(struct net_device *ndev, const u8 *addr, const char *why)
{
	scb_val_t scbval;

	re_log("re: refusing association: %s\n", why);
	memset(&scbval, 0, sizeof(scbval));
	memcpy(&scbval.ea, addr, ETHER_ADDR_LEN);
	scbval.val = htod32(WLAN_REASON_UNSPECIFIED);
	wl_dev_ioctl(ndev, WLC_DISASSOC, &scbval, sizeof(scbval));
	cfg80211_connect_result(ndev, addr, NULL, 0, NULL, 0, WLAN_STATUS_UNSPECIFIED_FAILURE, GFP_KERNEL);
}

static s32
wl_bss_connect_done(struct wl_cfg80211_priv *wl, struct net_device *ndev,
                    const wl_event_msg_t *e, void *data, bool completed)
{
	struct wl_cfg80211_connect_info *conn_info = wl_to_conn(wl);
	s32 err = 0;

	re_log("re: connect_done completed=%d connecting=%d\n", completed,
	       test_bit(WL_STATUS_CONNECTING, &wl->status));
	if (wl->scan_request) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		struct cfg80211_scan_info info = {
			.aborted = true
		};
		WL_DBG(("%s: Aborting scan\n", __FUNCTION__));
		cfg80211_scan_done(wl->scan_request, &info);
#else
		cfg80211_scan_done(wl->scan_request, true);
#endif
		wl->scan_request = NULL;
	}

	if (!completed && EVENT_TYPE(e) == WLC_E_SET_SSID && EVENT_STATUS(e) == WLC_E_STATUS_FAIL &&
	    wl_sae.join_len && wl_sae.retries < WL_SAE_MAX_RETRIES &&
	    test_bit(WL_STATUS_CONNECTING, &wl->status)) {
		re_log("re: join failed (AP status %u): retrying in %d ms\n", wl_sae.assoc_status,
		       WL_SAE_RETRY_DELAY_MS);
		wl_sae.assoc_status = 0;
		cancel_delayed_work(&wl_sae.assoc_wd);   /* the retry has its own timing */
		schedule_delayed_work(&wl_sae.retry_work, msecs_to_jiffies(WL_SAE_RETRY_DELAY_MS));
		return err;
	}
	if (test_and_clear_bit(WL_STATUS_CONNECTING, &wl->status)) {
		if (completed) {
			wl_get_assoc_ies(wl);
			if (re_verbose >= 2) {
				/* what the blob really put in the assoc request, and what the AP answered */
				s32 cs = -1, rt = -1;
				wl_dev_intvar_get(ndev, "chanspec", &cs);
				wl_dev_ioctl(ndev, WLC_GET_RATE, &rt, sizeof(rt));
				re_log("re: assoc: chanspec=0x%x rate=%d req_ie_len=%u resp_ie_len=%u\n", cs, dtoh32(rt),
				       conn_info->req_ie_len, conn_info->resp_ie_len);
				if (conn_info->req_ie)
					print_hex_dump(KERN_ERR, "re req_ie: ", DUMP_PREFIX_OFFSET, 32, 1, conn_info->req_ie,
					               min_t(u32, conn_info->req_ie_len, 512), false);
				if (conn_info->resp_ie)
					print_hex_dump(KERN_ERR, "re resp_ie: ", DUMP_PREFIX_OFFSET, 32, 1, conn_info->resp_ie,
					               min_t(u32, conn_info->resp_ie_len, 512), false);
			}
			if (re_verbose) {
				s32 wa = -1, ws = -1;
				wl_dev_intvar_get(ndev, "wpa_auth", &wa);
				wl_dev_intvar_get(ndev, "wsec", &ws);
				re_log("re: link up: wpa_auth=0x%x wsec=0x%x sae_conn=%d\n", wa, ws, wl_sae.sae_conn);
			}
			/* WPA3 guard: in an SAE connection the firmware must only ever associate AFTER
			 * the host SAE succeeded, with an RSN IE that offers SAE. Anything else is the
			 * blob's own Open/PSK join (e.g. on a transition-mode AP) -> refuse it. */
			if (wl_sae.sae_conn &&
			    (!wl_sae.sae_ok ||
			     wl_rsn_ie_has_sae(conn_info->req_ie, conn_info->req_ie_len) == 0)) {
				wl_refuse_assoc(ndev, (u8 *)&e->addr, "association without SAE");
				return -ECONNREFUSED;
			}
			memcpy(&wl->bssid, &e->addr, ETHER_ADDR_LEN);
			memcpy(wl->profile->bssid, &e->addr, ETHER_ADDR_LEN);
			wl_update_bss_info(wl);
			/* cfg80211 drops (with a WARN) a "connected" report for a BSS it has no entry for,
			 * and then wpa_supplicant never learns that we are up. Fail the attempt instead. */
			{
				struct cfg80211_bss *b = wl_get_ess_bss(wl);
				if (!b) {
					wl_refuse_assoc(ndev, (u8 *)&e->addr, "cfg80211 has no BSS entry for the AP");
					return -ECONNREFUSED;
				}
				cfg80211_put_bss(wl_to_wiphy(wl), b);
			}
			set_bit(WL_STATUS_CONNECTED, &wl->status);
			/* ptk_done is reset in .connect; the key may already be in by now */
			if (wl_sae.sae_conn && !wl_sae.ptk_done)
				schedule_delayed_work(&wl_sae.hs_wd, msecs_to_jiffies(WL_HS_TIMEOUT_MS));
		}

		WL_DBG(("Reporting BSS network join result \"%s\"\n",
			wl->profile->ssid.SSID));
		cfg80211_connect_result(ndev, (u8 *)&wl->bssid,	conn_info->req_ie,
		    conn_info->req_ie_len, conn_info->resp_ie, conn_info->resp_ie_len,
		    completed ? WLAN_STATUS_SUCCESS : WLAN_STATUS_AUTH_TIMEOUT,	GFP_KERNEL);
		WL_DBG(("Connection %s\n", completed ? "Succeeded" : "FAILed"));
	}

	return err;
}

static s32
wl_notify_mic_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
                     const wl_event_msg_t *e, void *data)
{
	u16 flags = EVENT_FLAGS(e);
	enum nl80211_key_type key_type;

	WL_DBG(("\n"));

	rtnl_lock();
	if (flags & WLC_EVENT_MSG_GROUP)
		key_type = NL80211_KEYTYPE_GROUP;
	else
		key_type = NL80211_KEYTYPE_PAIRWISE;

	cfg80211_michael_mic_failure(ndev, (u8 *)&e->addr, key_type, -1, NULL, GFP_KERNEL);
	rtnl_unlock();

	return 0;
}

static s32
wl_notify_scan_status(struct wl_cfg80211_priv *wl, struct net_device *ndev,
                      const wl_event_msg_t *e, void *data)
{
	struct channel_info channel_inform;
	struct wl_scan_results *bss_list;
	u32 buflen;
	s32 err = 0;

	WL_DBG(("\n"));

	rtnl_lock();
	err = wl_dev_ioctl(ndev, WLC_GET_CHANNEL, &channel_inform, sizeof(channel_inform));
	if (err) {
		WL_ERR(("scan busy (%d)\n", err));
		goto scan_done_out;
	}
	channel_inform.scan_channel = dtoh32(channel_inform.scan_channel);
	if (channel_inform.scan_channel) {

		WL_DBG(("channel_inform.scan_channel (%d)\n",	channel_inform.scan_channel));
	}

	for (buflen = WL_SCAN_BUF_BASE; ; ) {
		bss_list = (struct wl_scan_results *) kmalloc(buflen, GFP_KERNEL);
		if (!bss_list) {
			WL_ERR(("%s Out of memory for scan results, (%d)\n", ndev->name, err));
			goto scan_done_out;
		}
		memset(bss_list, 0, buflen);
		bss_list->buflen = htod32(buflen);
		err = wl_dev_ioctl(ndev, WLC_SCAN_RESULTS, bss_list, buflen);
		if (!err) {
			break;
		}
		else if (err == -E2BIG) {
			kfree(bss_list);
			buflen *= 2;
		}
		else {
			WL_ERR(("%s Scan_results error (%d)\n", ndev->name, err));
			kfree(bss_list);
			err = -EINVAL;
			goto scan_done_out;
		}
	}

	bss_list->buflen = dtoh32(bss_list->buflen);
	bss_list->version = dtoh32(bss_list->version);
	bss_list->count = dtoh32(bss_list->count);

	err = wl_inform_bss(wl, bss_list);
	kfree(bss_list);

scan_done_out:
	if (wl->scan_request) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		struct cfg80211_scan_info info = {
			.aborted = false
		};
		cfg80211_scan_done(wl->scan_request, &info);
#else
		cfg80211_scan_done(wl->scan_request, false);
#endif
		wl->scan_request = NULL;
	}
	rtnl_unlock();
	return err;
}

static void wl_init_conf(struct wl_cfg80211_conf *conf)
{
	conf->mode = (u32)-1;
	conf->frag_threshold = (u32)-1;
	conf->rts_threshold = (u32)-1;
	conf->retry_short = (u32)-1;
	conf->retry_long = (u32)-1;
	conf->tx_power = -1;
}

static void wl_init_prof(struct wl_cfg80211_profile *prof)
{
	memset(prof, 0, sizeof(*prof));
}

static void wl_init_eloop_handler(struct wl_cfg80211_event_loop *el)
{
	memset(el, 0, sizeof(*el));
	el->handler[WLC_E_SCAN_COMPLETE] = wl_notify_scan_status;
	el->handler[WLC_E_JOIN] = wl_notify_connect_status;
	el->handler[WLC_E_START] = wl_notify_connect_status;
	el->handler[WLC_E_LINK] = wl_notify_connect_status;
	el->handler[WLC_E_NDIS_LINK] = wl_notify_connect_status;
	el->handler[WLC_E_SET_SSID] = wl_notify_connect_status;
	el->handler[WLC_E_DISASSOC_IND] = wl_notify_connect_status;
	el->handler[WLC_E_DEAUTH_IND] = wl_notify_connect_status;
	el->handler[WLC_E_ROAM] = wl_notify_roaming_status;
	el->handler[WLC_E_MIC_ERROR] = wl_notify_mic_status;
}

static s32 wl_init_priv_mem(struct wl_cfg80211_priv *wl)
{
	wl->conf = (void *)kzalloc(sizeof(*wl->conf), GFP_KERNEL);
	if (!wl->conf) {
		WL_ERR(("wl_cfg80211_conf alloc failed\n"));
		goto init_priv_mem_out;
	}
	wl->profile = (void *)kzalloc(sizeof(*wl->profile), GFP_KERNEL);
	if (!wl->profile) {
		WL_ERR(("wl_cfg80211_profile alloc failed\n"));
		goto init_priv_mem_out;
	}
	wl->scan_req_int = (void *)kzalloc(sizeof(*wl->scan_req_int), GFP_KERNEL);
	if (!wl->scan_req_int) {
		WL_ERR(("Scan req alloc failed\n"));
		goto init_priv_mem_out;
	}
	wl->ioctl_buf = (void *)kzalloc(WL_IOCTL_LEN_MAX, GFP_KERNEL);
	if (!wl->ioctl_buf) {
		WL_ERR(("Ioctl buf alloc failed\n"));
		goto init_priv_mem_out;
	}
	wl->extra_buf = (void *)kzalloc(WL_EXTRA_BUF_MAX, GFP_KERNEL);
	if (!wl->extra_buf) {
		WL_ERR(("Extra buf alloc failed\n"));
		goto init_priv_mem_out;
	}

	wl->pmk_list = (void *)kzalloc(sizeof(*wl->pmk_list), GFP_KERNEL);
	if (!wl->pmk_list) {
		WL_ERR(("pmk list alloc failed\n"));
		goto init_priv_mem_out;
	}

	return 0;

init_priv_mem_out:
	wl_deinit_priv_mem(wl);

	return -ENOMEM;
}

static void wl_deinit_priv_mem(struct wl_cfg80211_priv *wl)
{
	kfree(wl->conf);
	wl->conf = NULL;
	kfree(wl->profile);
	wl->profile = NULL;
	kfree(wl->scan_req_int);
	wl->scan_req_int = NULL;
	kfree(wl->ioctl_buf);
	wl->ioctl_buf = NULL;
	kfree(wl->extra_buf);
	wl->extra_buf = NULL;
	kfree(wl->pmk_list);
	wl->pmk_list = NULL;
}

static s32 wl_create_event_handler(struct wl_cfg80211_priv *wl)
{
	sema_init(&wl->event_sync, 0);
	wl->event_tsk = kthread_run(wl_event_handler, wl, "wl_event_handler");
	if (IS_ERR(wl->event_tsk)) {
		wl->event_tsk = NULL;
		WL_ERR(("failed to create event thread\n"));
		return -ENOMEM;
	}
	return 0;
}

static void wl_destroy_event_handler(struct wl_cfg80211_priv *wl)
{
	if (wl->event_tsk) {
		send_sig(SIGTERM, wl->event_tsk, 1);
		kthread_stop(wl->event_tsk);
		wl->event_tsk = NULL;
	}
}

static s32 wl_init_cfg80211_priv(struct wl_cfg80211_priv *wl, struct wireless_dev *wdev)
{
	s32 err = 0;

	wl->wdev = wdev;

	wl->scan_request = NULL;
	wl->active_scan = true;
	wl_init_eq(wl);
	err = wl_init_priv_mem(wl);
	if (err)
		return err;

	if (wl_create_event_handler(wl))
		return -ENOMEM;

	wl_init_eloop_handler(&wl->el);

	if (err)
		return err;

	wl_init_conf(wl->conf);
	wl_init_prof(wl->profile);
	wl_link_down(wl);

	return err;
}

static void wl_deinit_cfg80211_priv(struct wl_cfg80211_priv *wl)
{
	wl_destroy_event_handler(wl);
	wl_flush_eq(wl);
	wl_link_down(wl);
	wl_deinit_priv_mem(wl);
}

s32 wl_cfg80211_attach(struct net_device *ndev, struct device *dev, int passive)
{
	struct wireless_dev *wdev;
	struct wl_cfg80211_priv *wl;
	s32 err = 0;

	if (!ndev) {
		WL_ERR(("ndev is invaild\n"));
		return -ENODEV;
	}

	err = wl_alloc_wdev(dev, &wdev);
	if (err < 0) {
		return err;
	}

	wdev->iftype = wl_mode_to_nl80211_iftype(WL_MODE_BSS);
	wl = wdev_to_wl(wdev);
	ndev->ieee80211_ptr = wdev;
	SET_NETDEV_DEV(ndev, wiphy_dev(wdev->wiphy));
	wdev->netdev = ndev;
	err = wl_init_cfg80211_priv(wl, wdev);
	if (err) {
		WL_ERR(("Failed to init iwm_priv (%d)\n", err));
		goto cfg80211_attach_out;
	}
	wl->passive = !!passive;

	if (!err) {
		WL_INF(("Registered CFG80211 phy\n"));
	}
	return err;

cfg80211_attach_out:
	wl_free_wdev(wl);
	return err;
}

void wl_cfg80211_detach(struct net_device *ndev)
{
	struct wl_cfg80211_priv *wl;

	if (ndev->ieee80211_ptr == NULL) {
                WL_ERR(( "NULL ndev->ieee80211ptr, unable to deref wl\n"));
                return;
        }
	wl = ndev_to_wl(ndev);

	if (wl_sae.inited) {
		cancel_delayed_work_sync(&wl_sae.work);
		cancel_delayed_work_sync(&wl_sae.assoc_wd);
		cancel_delayed_work_sync(&wl_sae.saq_chk);
		cancel_delayed_work_sync(&wl_sae.retry_work);
		cancel_delayed_work_sync(&wl_sae.join_work);
		cancel_delayed_work_sync(&wl_sae.hs_wd);
		cancel_work_sync(&wl_sae.saq_work);
		cancel_work_sync(&wl_sae.dd_work);
	}
	wl_re_crypto_exit();
	wl_deinit_cfg80211_priv(wl);
	wl_free_wdev(wl);
}

static void wl_wakeup_event(struct wl_cfg80211_priv *wl)
{
	up(&wl->event_sync);
}

static s32 wl_event_handler(void *data)
{
	struct wl_cfg80211_priv *wl = (struct wl_cfg80211_priv *)data;
	struct wl_cfg80211_event_q *e;

	allow_signal(SIGTERM);
	while (!down_interruptible(&wl->event_sync)) {
		if (kthread_should_stop())
			break;
		e = wl_deq_event(wl);
		if (!e) {
			WL_ERR(("eqeue empty..\n"));
			BUG();
		}
		if (wl->el.handler[e->etype]) {
			WL_DBG(("event type (%d)\n", e->etype));
			wl->el.handler[e->etype] (wl, wl_to_ndev(wl), &e->emsg, e->edata);
		} else {
			WL_DBG(("Unknown Event (%d): ignoring\n", e->etype));
		}
		wl_put_event(e);
	}
	WL_DBG(("%s was terminated\n", __func__));
	return 0;
}

void
wl_cfg80211_event(struct net_device *ndev, const wl_event_msg_t * e, void *data)
{

	u32 event_type = EVENT_TYPE(e);

	struct wl_cfg80211_priv *wl = ndev_to_wl(ndev);
	/* every firmware event (TXFAIL, MIC_ERROR, PSK_SUP, DEAUTH, ...), verbose only; scan results are noise */
	if (event_type == WLC_E_TXFAIL)
		atomic_inc(&wl_sae.txfail_cnt);
	else if (event_type == WLC_E_ASSOC)
		wl_sae.assoc_status = dtoh32(e->reason);   /* 802.11 status code from the AP's response */
	if (event_type != WLC_E_SCAN_COMPLETE)
		re_log("re: fw event %u status=%u reason=%u flags=0x%x\n", event_type, EVENT_STATUS(e),
		       dtoh32(e->reason), EVENT_FLAGS(e));
#if defined(WL_DBGMSG_ENABLE)
	s8 *estr = (event_type <= sizeof(wl_dbg_estr) / WL_DBG_ESTR_MAX - 1) ?
	    wl_dbg_estr[event_type] : (s8 *) "Unknown";
	WL_DBG(("event_type (%d):" "WLC_E_" "%s\n", event_type, estr));
#endif				
	if (!wl_enq_event(wl, event_type, e, data))
		wl_wakeup_event(wl);
}

static void wl_init_eq(struct wl_cfg80211_priv *wl)
{
	wl_init_eq_lock(wl);
	INIT_LIST_HEAD(&wl->eq_list);
}

static void wl_flush_eq(struct wl_cfg80211_priv *wl)
{
	struct wl_cfg80211_event_q *e;

	wl_lock_eq(wl);
	while (!list_empty(&wl->eq_list)) {
		e = list_first_entry(&wl->eq_list, struct wl_cfg80211_event_q, eq_list);
		list_del(&e->eq_list);
		kfree(e);
	}
	wl_unlock_eq(wl);
}

static struct wl_cfg80211_event_q *wl_deq_event(struct wl_cfg80211_priv *wl)
{
	struct wl_cfg80211_event_q *e = NULL;

	wl_lock_eq(wl);
	if (!list_empty(&wl->eq_list)) {
		e = list_first_entry(&wl->eq_list, struct wl_cfg80211_event_q, eq_list);
		list_del(&e->eq_list);
	}
	wl_unlock_eq(wl);

	return e;
}

static s32
wl_enq_event(struct wl_cfg80211_priv *wl, u32 event, const wl_event_msg_t *msg, void *data)
{
	struct wl_cfg80211_event_q *e;
	s32 err = 0;

	e = kzalloc(sizeof(struct wl_cfg80211_event_q), GFP_ATOMIC);
	if (!e) {
		WL_ERR(("event alloc failed\n"));
		return -ENOMEM;
	}

	e->etype = event;
	memcpy(&e->emsg, msg, sizeof(wl_event_msg_t));
	if (data) {
	}

	spin_lock(&wl->eq_lock);
	list_add_tail(&e->eq_list, &wl->eq_list);
	spin_unlock(&wl->eq_lock);

	return err;
}

static void wl_put_event(struct wl_cfg80211_event_q *e)
{
	kfree(e);
}

static s32 wl_set_mode(struct net_device *ndev, s32 iftype)
{
	s32 infra = 0;
	s32 ap = 0;
	s32 err = 0;

	switch (iftype) {
	case NL80211_IFTYPE_MONITOR:
	case NL80211_IFTYPE_WDS:
		WL_ERR(("type (%d) : currently we do not support this mode\n",
			iftype));
		err = -EINVAL;
		return err;
	case NL80211_IFTYPE_ADHOC:
		break;
	case NL80211_IFTYPE_STATION:
		infra = 1;
		break;
	default:
		err = -EINVAL;
		WL_ERR(("invalid type (%d)\n", iftype));
		return err;
	}
	infra = htod32(infra);
	ap = htod32(ap);
	WL_DBG(("%s ap (%d), infra (%d)\n", ndev->name, ap, infra));
	err = wl_dev_ioctl(ndev, WLC_SET_INFRA, &infra, sizeof(infra));
	if (err) {
		WL_ERR(("WLC_SET_INFRA error (%d)\n", err));
		return err;
	}
	err = wl_dev_ioctl(ndev, WLC_SET_AP, &ap, sizeof(ap));
	if (err) {
		WL_ERR(("WLC_SET_AP error (%d)\n", err));
		return err;
	}

	return 0;
}

static void wl_update_wowl(struct net_device *ndev)
{
#ifdef CONFIG_PM
	struct wl_cfg80211_priv *wl = ndev_to_wl(ndev);
	struct wireless_dev *wdev = ndev->ieee80211_ptr;
	s32 offloads = 0;
	s32 err = 0;
	err = wl_dev_bufvar_get(wl_to_ndev(wl), "offloads",
		(s8 *)&offloads, sizeof(offloads));
	if (err == 0 && offloads == 1) {
		WL_INF(("Supports offloads\n"));
		wl->offloads = true;
	} else {
		WL_INF(("No offloads supported\n"));
		wl->offloads = false;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
		wdev->wiphy->wowlan = NULL;
#else
		memset(&wdev->wiphy->wowlan, 0, sizeof(struct wiphy_wowlan_support));
#endif 
#endif 
	}
#endif 
}

static s32 wl_update_wiphybands(struct wl_cfg80211_priv *wl)
{
	struct wiphy *wiphy;
	s32 phy_list;
	s8 phy;
	s32 err = 0;

	err = wl_dev_ioctl(wl_to_ndev(wl), WLC_GET_PHYLIST, &phy_list, sizeof(phy_list));
	if (err) {
		WL_ERR(("error (%d)\n", err));
		return err;
	}

	phy = ((char *)&phy_list)[0];
	WL_DBG(("%c phy\n", phy));

	if (phy == 'n' || phy == 'a' || phy == 'v') {
		wiphy = wl_to_wiphy(wl);
		wiphy->bands[NL80211_BAND_5GHZ] = &__wl_band_5ghz_n;
	}

	return err;
}

s32 wl_cfg80211_up(struct net_device *ndev)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(ndev);
	s32 err = 0;
	struct wireless_dev *wdev = ndev->ieee80211_ptr;

	wl_set_mode(ndev, wdev->iftype);
	err = wl_update_wiphybands(wl);
	if (err) {
		return err;
	} 

	wl_update_wowl(ndev);
	return 0;
}

s32 wl_cfg80211_down(struct net_device *ndev)
{
	struct wl_cfg80211_priv *wl = ndev_to_wl(ndev);
	s32 err = 0;

	if (wl->scan_request) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		struct cfg80211_scan_info info = {
			.aborted = true
		};
		cfg80211_scan_done(wl->scan_request, &info);
#else
		cfg80211_scan_done(wl->scan_request, true);
#endif
		wl->scan_request = NULL;
	}

	return err;
}

static bool wl_is_ibssmode(struct wl_cfg80211_priv *wl)
{
	return wl->conf->mode == WL_MODE_IBSS;
}

static void wl_rst_ie(struct wl_cfg80211_priv *wl)
{
	struct wl_cfg80211_ie *ie = wl_to_ie(wl);

	ie->offset = 0;
}

static __used s32 wl_add_ie(struct wl_cfg80211_priv *wl, u8 t, u8 l, u8 *v)
{
	struct wl_cfg80211_ie *ie = wl_to_ie(wl);
	s32 err = 0;

	if (ie->offset + l + 2 > WL_TLV_INFO_MAX) {
		WL_ERR(("ei crosses buffer boundary\n"));
		return -ENOSPC;
	}
	ie->buf[ie->offset] = t;
	ie->buf[ie->offset + 1] = l;
	memcpy(&ie->buf[ie->offset + 2], v, l);
	ie->offset += l + 2;

	return err;
}

static s32 wl_mrg_ie(struct wl_cfg80211_priv *wl, u8 *ie_stream, u16 ie_size)
{
	struct wl_cfg80211_ie *ie = wl_to_ie(wl);
	s32 err = 0;

	if (ie->offset + ie_size > WL_TLV_INFO_MAX) {
		WL_ERR(("ei_stream crosses buffer boundary\n"));
		return -ENOSPC;
	}
	memcpy(&ie->buf[ie->offset], ie_stream, ie_size);
	ie->offset += ie_size;

	return err;
}

static s32 wl_cp_ie(struct wl_cfg80211_priv *wl, u8 *dst, u16 dst_size)
{
	struct wl_cfg80211_ie *ie = wl_to_ie(wl);
	s32 err = 0;

	if (ie->offset > dst_size) {
		WL_ERR(("dst_size is not enough\n"));
		return -ENOSPC;
	}
	memcpy(dst, &ie->buf[0], ie->offset);

	return err;
}

static u32 wl_get_ielen(struct wl_cfg80211_priv *wl)
{
	struct wl_cfg80211_ie *ie = wl_to_ie(wl);

	return ie->offset;
}

static void wl_link_up(struct wl_cfg80211_priv *wl)
{
	WL_DBG(("\n"));
}

static void wl_link_down(struct wl_cfg80211_priv *wl)
{
	struct wl_cfg80211_connect_info *conn_info = wl_to_conn(wl);

	WL_DBG(("\n"));

	kfree(conn_info->req_ie);
	conn_info->req_ie = NULL;
	conn_info->req_ie_len = 0;
	kfree(conn_info->resp_ie);
	conn_info->resp_ie = NULL;
	conn_info->resp_ie_len = 0;
}

static void wl_lock_eq(struct wl_cfg80211_priv *wl)
{
	spin_lock_irq(&wl->eq_lock);
}

static void wl_unlock_eq(struct wl_cfg80211_priv *wl)
{
	spin_unlock_irq(&wl->eq_lock);
}

static void wl_init_eq_lock(struct wl_cfg80211_priv *wl)
{
	spin_lock_init(&wl->eq_lock);
}

#endif 
