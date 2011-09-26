/*
 * arch/arm/mach-tegra/board-antares.h
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _MACH_TEGRA_BOARD_ANTARES_H
#define _MACH_TEGRA_BOARD_ANTARES_H

int antares_charge_init(void);
int antares_regulator_init(void);
int antares_sdhci_init(void);
int antares_pinmux_init(void);
int antares_panel_init(void);
int antares_wired_jack_init(void);
int antares_sensors_init(void);
int antares_kbc_init(void);
int antares_emc_init(void);
int antares_ec_init(void);

/* external gpios */

/* TPS6586X gpios */
#define TPS6586X_GPIO_BASE	TEGRA_NR_GPIOS

/* WM8903 gpios */
#define WM8903_GPIO_BASE	(TEGRA_NR_GPIOS + 32)
#define WM8903_GP1		(WM8903_GPIO_BASE + 0)
#define WM8903_GP2		(WM8903_GPIO_BASE + 1)
#define WM8903_GP3		(WM8903_GPIO_BASE + 2)
#define WM8903_GP4		(WM8903_GPIO_BASE + 3)
#define WM8903_GP5		(WM8903_GPIO_BASE + 4)

/* Interrupt numbers from external peripherals */
#define TPS6586X_INT_BASE	TEGRA_NR_IRQS
#define TPS6586X_INT_END	(TPS6586X_INT_BASE + 32)

#define NCT1008_SHUTDOWN_EXT_LIMIT      115
#define NCT1008_SHUTDOWN_LOCAL_LIMIT    88
#define NCT1008_THROTTLE_EXT_LIMIT      90

#endif
