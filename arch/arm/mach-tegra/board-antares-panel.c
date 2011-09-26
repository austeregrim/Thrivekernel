/*
 * arch/arm/mach-tegra/board-antares-panel.c
 *
 * Copyright (c) 2010, NVIDIA Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/regulator/consumer.h>
#include <linux/resource.h>
#include <asm/mach-types.h>
#include <linux/platform_device.h>
#include <linux/earlysuspend.h>
#include <linux/pwm_backlight.h>
#include <mach/nvhost.h>
#include <mach/nvmap.h>
#include <mach/irqs.h>
#include <mach/iomap.h>
#include <mach/dc.h>
#include <mach/fb.h>

#include "devices.h"
#include "gpio-names.h"
#include "board.h"

#define antares_pnl_pwr_enb	TEGRA_GPIO_PC6
#define antares_bl_enb		TEGRA_GPIO_PD4
#define antares_lvds_shutdown	TEGRA_GPIO_PB2
#define antares_hdmi_hpd	TEGRA_GPIO_PN7
#define antares_hdmi_enb	TEGRA_GPIO_PV5

static struct regulator *antares_hdmi_reg = NULL;
static struct regulator *antares_hdmi_pll = NULL;
static int panel_enable = 1;
static int backlight_on = 1;

static int antares_panel_enable(void)
{
	struct regulator *reg = regulator_get(NULL, "vdd_ldo4");

	regulator_enable(reg);
	regulator_put(reg);
	if (panel_enable)
		return 0;

	gpio_set_value(antares_pnl_pwr_enb, 1);
	mdelay(5);
	gpio_set_value(antares_lvds_shutdown, 1);
	mdelay(205);
	panel_enable = 1;
	return 0;
}

static int antares_panel_disable(void)
{
	/* wait for backlight off */
	if (!backlight_on) {
		mdelay(205);
		gpio_set_value(antares_lvds_shutdown, 0);
		mdelay(5);
		gpio_set_value(antares_pnl_pwr_enb, 0);
	}

	panel_enable = 0;
	return 0;
}

static int antares_hdmi_enable(void)
{
	if (!antares_hdmi_reg) {
		antares_hdmi_reg = regulator_get(NULL, "avdd_hdmi"); /* LD07 */
		if (IS_ERR_OR_NULL(antares_hdmi_reg)) {
			pr_err("hdmi: couldn't get regulator avdd_hdmi\n");
			antares_hdmi_reg = NULL;
			return PTR_ERR(antares_hdmi_reg);
		}
	}
	regulator_enable(antares_hdmi_reg);

	if (!antares_hdmi_pll) {
		antares_hdmi_pll = regulator_get(NULL, "avdd_hdmi_pll"); /* LD08 */
		if (IS_ERR_OR_NULL(antares_hdmi_pll)) {
			pr_err("hdmi: couldn't get regulator avdd_hdmi_pll\n");
			antares_hdmi_pll = NULL;
			regulator_disable(antares_hdmi_reg);
			antares_hdmi_reg = NULL;
			return PTR_ERR(antares_hdmi_pll);
		}
	}
	regulator_enable(antares_hdmi_pll);
	return 0;
}

static int antares_hdmi_disable(void)
{
	regulator_disable(antares_hdmi_reg);
	regulator_disable(antares_hdmi_pll);
	return 0;
}

static struct resource antares_disp1_resources[] = {
	{
		.name	= "irq",
		.start	= INT_DISPLAY_GENERAL,
		.end	= INT_DISPLAY_GENERAL,
		.flags	= IORESOURCE_IRQ,
	},
	{
		.name	= "regs",
		.start	= TEGRA_DISPLAY_BASE,
		.end	= TEGRA_DISPLAY_BASE + TEGRA_DISPLAY_SIZE - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.name	= "fbmem",
		.flags	= IORESOURCE_MEM,
	},
};

static struct resource antares_disp2_resources[] = {
	{
		.name	= "irq",
		.start	= INT_DISPLAY_B_GENERAL,
		.end	= INT_DISPLAY_B_GENERAL,
		.flags	= IORESOURCE_IRQ,
	},
	{
		.name	= "regs",
		.start	= TEGRA_DISPLAY2_BASE,
		.end	= TEGRA_DISPLAY2_BASE + TEGRA_DISPLAY2_SIZE - 1,
		.flags	= IORESOURCE_MEM,
	},
	{
		.name	= "fbmem",
		.flags	= IORESOURCE_MEM,
	},
	{
		.name	= "hdmi_regs",
		.start	= TEGRA_HDMI_BASE,
		.end	= TEGRA_HDMI_BASE + TEGRA_HDMI_SIZE - 1,
		.flags	= IORESOURCE_MEM,
	},
};

static struct tegra_dc_mode antares_panel_modes[] = {
	{
		.pclk = 72072000,
		.h_ref_to_sync = 11,
		.v_ref_to_sync = 1,
		.h_sync_width = 58,
		.v_sync_width = 4,
		.h_back_porch = 58,
		.v_back_porch = 4,
		.h_active = 1366,
		.v_active = 768,
		.h_front_porch = 58,
		.v_front_porch = 4,
	},
};

static struct tegra_fb_data antares_fb_data = {
	.win		= 0,
	.xres		= 1366,
	.yres		= 768,
	.bits_per_pixel	= 32,
};

static struct tegra_fb_data antares_hdmi_fb_data = {
	.win		= 0,
	.xres		= 1366,
	.yres		= 768,
	.bits_per_pixel	= 32,
};

static struct tegra_dc_out antares_disp1_out = {
	.type		= TEGRA_DC_OUT_RGB,

	.dcc_bus	= 2,
	.align		= TEGRA_DC_ALIGN_MSB,
	.order		= TEGRA_DC_ORDER_RED_BLUE,
	.depth		= 18,
	.dither		= TEGRA_DC_ORDERED_DITHER,

	.modes	 	= antares_panel_modes,
	.n_modes 	= ARRAY_SIZE(antares_panel_modes),

	.enable		= antares_panel_enable,
	.disable	= antares_panel_disable,
};

static struct tegra_dc_out antares_disp2_out = {
	.type		= TEGRA_DC_OUT_HDMI,
	.flags		= TEGRA_DC_OUT_HOTPLUG_HIGH,

	.dcc_bus	= 1,
	.hotplug_gpio	= antares_hdmi_hpd,

	.align		= TEGRA_DC_ALIGN_MSB,
	.order		= TEGRA_DC_ORDER_RED_BLUE,

	.enable		= antares_hdmi_enable,
	.disable	= antares_hdmi_disable,
};

static struct tegra_dc_platform_data antares_disp1_pdata = {
	.flags		= TEGRA_DC_FLAG_ENABLED,
	.default_out	= &antares_disp1_out,
	.fb		= &antares_fb_data,
};

static struct tegra_dc_platform_data antares_disp2_pdata = {
	.flags		= 0,
	.default_out	= &antares_disp2_out,
	.fb		= &antares_hdmi_fb_data,
};

static struct nvhost_device antares_disp1_device = {
	.name		= "tegradc",
	.id		= 0,
	.resource	= antares_disp1_resources,
	.num_resources	= ARRAY_SIZE(antares_disp1_resources),
	.dev = {
		.platform_data = &antares_disp1_pdata,
	},
};

static int antares_disp1_check_fb(struct device *dev, struct fb_info *info)
{
	return info->device == &antares_disp1_device.dev;
}

static struct nvhost_device antares_disp2_device = {
	.name		= "tegradc",
	.id		= 1,
	.resource	= antares_disp2_resources,
	.num_resources	= ARRAY_SIZE(antares_disp2_resources),
	.dev = {
		.platform_data = &antares_disp2_pdata,
	},
};

static struct nvmap_platform_carveout antares_carveouts[] = {
	[0] = {
		.name		= "iram",
		.usage_mask	= NVMAP_HEAP_CARVEOUT_IRAM,
		.base		= TEGRA_IRAM_BASE,
		.size		= TEGRA_IRAM_SIZE,
		.buddy_size	= 0, /* no buddy allocation for IRAM */
	},
	[1] = {
		.name		= "generic-0",
		.usage_mask	= NVMAP_HEAP_CARVEOUT_GENERIC,
		.buddy_size	= SZ_32K,
	},
};

static struct nvmap_platform_data antares_nvmap_data = {
	.carveouts	= antares_carveouts,
	.nr_carveouts	= ARRAY_SIZE(antares_carveouts),
};

static struct platform_device antares_nvmap_device = {
	.name	= "tegra-nvmap",
	.id	= -1,
	.dev	= {
		.platform_data = &antares_nvmap_data,
	},
};

static int antares_backlight_notify(struct device *unused, int brightness)
{
	if (!(backlight_on ^ !!brightness))
		return brightness;

	backlight_on = (!!brightness) & panel_enable;
	gpio_set_value(antares_bl_enb, backlight_on);
	if (!brightness && !panel_enable)
		antares_panel_disable();

	return brightness;
}

static int antares_backlight_init(struct device *dev) {
	gpio_request(antares_bl_enb, "backlight_enb");
	tegra_gpio_enable(antares_bl_enb);
	return 0;
};

static void antares_backlight_exit(struct device *dev) {
	antares_backlight_notify(dev, 0);
	gpio_free(antares_bl_enb);
	tegra_gpio_disable(antares_bl_enb);
}

static struct platform_pwm_backlight_data antares_backlight_data = {
	.pwm_id		= 2,
	.max_brightness	= 255,
	.dft_brightness	= 224,
	.pwm_period_ns	= 62500,
	.init		= antares_backlight_init,
	.exit		= antares_backlight_exit,
	.notify		= antares_backlight_notify,
	/* Only toggle backlight on fb blank notifications for disp1 */
	.check_fb   = antares_disp1_check_fb,
};

static struct platform_device antares_backlight_device = {
	.name	= "pwm-backlight",
	.id	= -1,
	.dev	= {
		.platform_data = &antares_backlight_data,
	},
};

static struct platform_device *antares_gfx_devices[] __initdata = {
	&antares_nvmap_device,
	&tegra_grhost_device,
	&tegra_pwfm2_device,
	&antares_backlight_device,
};

#ifdef CONFIG_HAS_EARLYSUSPEND
/* put early_suspend/late_resume handlers here for the display in order
 * to keep the code out of the display driver, keeping it closer to upstream
 */
struct early_suspend antares_panel_early_suspender;

static void antares_panel_early_suspend(struct early_suspend *h)
{
	if (num_registered_fb > 0)
		fb_blank(registered_fb[0], FB_BLANK_POWERDOWN);
}

static void antares_panel_late_resume(struct early_suspend *h)
{
	if (num_registered_fb > 0)
		fb_blank(registered_fb[0], FB_BLANK_UNBLANK);
}
#endif

int __init antares_panel_init(void)
{
	int err;
	struct resource *res;

	gpio_request(antares_pnl_pwr_enb, "pnl_pwr_enb");
	tegra_gpio_enable(antares_pnl_pwr_enb);

	gpio_request(antares_lvds_shutdown, "lvds_shdn");
	tegra_gpio_enable(antares_lvds_shutdown);

	tegra_gpio_enable(antares_hdmi_enb);
	gpio_request(antares_hdmi_enb, "hdmi_5v_en");
	gpio_direction_output(antares_hdmi_enb, 1);

	tegra_gpio_enable(antares_hdmi_hpd);
	gpio_request(antares_hdmi_hpd, "hdmi_hpd");
	gpio_direction_input(antares_hdmi_hpd);

#ifdef CONFIG_HAS_EARLYSUSPEND
	antares_panel_early_suspender.suspend = antares_panel_early_suspend;
	antares_panel_early_suspender.resume = antares_panel_late_resume;
	antares_panel_early_suspender.level = EARLY_SUSPEND_LEVEL_DISABLE_FB;
	register_early_suspend(&antares_panel_early_suspender);
#endif

	antares_carveouts[1].base = tegra_carveout_start;
	antares_carveouts[1].size = tegra_carveout_size;

	err = platform_add_devices(antares_gfx_devices,
				   ARRAY_SIZE(antares_gfx_devices));

	res = nvhost_get_resource_byname(&antares_disp1_device,
		IORESOURCE_MEM, "fbmem");
	res->start = tegra_fb_start;
	res->end = tegra_fb_start + tegra_fb_size - 1;

	res = nvhost_get_resource_byname(&antares_disp2_device,
		IORESOURCE_MEM, "fbmem");
	res->start = tegra_fb2_start;
	res->end = tegra_fb2_start + tegra_fb2_size - 1;

	if (!err)
		err = nvhost_device_register(&antares_disp1_device);

	if (!err)
		err = nvhost_device_register(&antares_disp2_device);

	return err;
}

