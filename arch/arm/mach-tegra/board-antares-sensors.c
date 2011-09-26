/*
 * arch/arm/mach-tegra/board-antares-sensors.c
 *
 * Copyright (c) 2011, NVIDIA, All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/akm8975.h>
#include <linux/mpu.h>
#include <linux/i2c/pca954x.h>
#include <linux/i2c/pca953x.h>
#include <linux/nct1008.h>
#include <linux/err.h>
#include <linux/regulator/consumer.h>
#include <mach/gpio.h>
#ifdef CONFIG_VIDEO_MT9P111
#include <media/mt9p111.h>
#endif
#ifdef CONFIG_VIDEO_MT9D115
#include <media/mt9d115.h>
#endif
#include <generated/mach-types.h>

#ifdef CONFIG_INPUT_MICROCHIP_I2C
#include <linux/i2c/microchip_i2c.h>
#endif

#include "gpio-names.h"
#include "board.h"
#include "board-antares.h"

#define AVDD_DSI_CSI_ENB_GPIO   TPS6586X_GPIO_BASE + 1

/* TCA6416 gpios */
#define TCA6416_GPIO_BASE       TEGRA_NR_GPIOS + 4
#define CAM_PRI_PWR_DN_GPIO     TCA6416_GPIO_BASE + 4
#define CAM_PRI_RST_GPIO        TCA6416_GPIO_BASE + 5
#define CAM_PRI_LDO_EN_GPIO     TCA6416_GPIO_BASE + 7
#define CAM_SEC_PWR_DN_GPIO     TCA6416_GPIO_BASE + 8
#define CAM_SEC_RST_GPIO        TCA6416_GPIO_BASE + 9
#define CAM_SEC_LDO_EN_GPIO     TCA6416_GPIO_BASE + 11
#define CAM_SEC_LED_GPIO        TCA6416_GPIO_BASE + 12
#define CAM_I2C_MUX_RST_GPIO    TCA6416_GPIO_BASE + 15

#define ISL29018_IRQ_GPIO       TEGRA_GPIO_PZ2
#define AKM8975_IRQ_GPIO        TEGRA_GPIO_PN5
#define CAMERA_POWER_GPIO       TEGRA_GPIO_PV4
#define AC_PRESENT_GPIO         TEGRA_GPIO_PV3
#define NCT1008_THERM2_GPIO     TEGRA_GPIO_PN6

#define CAMERA_GPIO(_name, _gpio, _enabled, _milliseconds)      \
	{                                                       \
		.name = _name,                                  \
		.gpio = _gpio,                                  \
		.enabled = _enabled,                            \
		.milliseconds = _milliseconds,                  \
	}

struct camera_gpios {
	const char *name;
	int gpio;
	int enabled;
	int milliseconds;
};

extern void tegra_throttling_enable(bool enable);

struct i2c_client *pca9543_i2c_client;

static struct pca953x_platform_data antares_tca6416_data = {
	.gpio_base      = TEGRA_NR_GPIOS + 4, /* 4 gpios are already requested by tps6586x */
};

static struct pca954x_platform_mode antares_pca9543_modes[] = {
	{ .adap_id = 6, .deselect_on_exit = 1 }, /* REAR CAM */
	{ .adap_id = 7, .deselect_on_exit = 1 }, /* FRONT CAM */
};

static struct pca954x_platform_data antares_pca9543_data = {
	.modes	  = antares_pca9543_modes,
	.num_modes      = ARRAY_SIZE(antares_pca9543_modes),
};

static const struct i2c_board_info antares_i2c3_board_info_tca6416[] = {
	{
		I2C_BOARD_INFO("tca6416", 0x20),
		.platform_data = &antares_tca6416_data,
	},
};

static const struct i2c_board_info antares_i2c3_board_info_pca9543[] = {
	{
		I2C_BOARD_INFO("pca9543", 0x70),
		.platform_data = &antares_pca9543_data,
	},
};

#ifdef CONFIG_VIDEO_MT9P111
static const struct camera_gpios mt9p111_gpio_keys[] = {
	[0] = CAMERA_GPIO("en_avdd_csi", AVDD_DSI_CSI_ENB_GPIO, 1, 1),
	[1] = CAMERA_GPIO("cam_pri_pwr_dn", CAM_PRI_PWR_DN_GPIO, 0, 1),
	[2] = CAMERA_GPIO("cam_pri_ldo_en", CAM_PRI_LDO_EN_GPIO, 1, 1),
	[3] = CAMERA_GPIO("cam_pri_rst", CAM_PRI_RST_GPIO, 1, 0),
};

static int antares_mt9p111_power_on(void)
{
	int i, ret = 0;

	gpio_direction_output(CAMERA_POWER_GPIO, 1);
	mdelay(1);
	gpio_direction_output(CAM_I2C_MUX_RST_GPIO, 1);
	mdelay(1);
	i2c_smbus_write_byte_data(pca9543_i2c_client, 0, 1);
	mdelay(1);
	for (i = 0; i < ARRAY_SIZE(mt9p111_gpio_keys); i++) {
		gpio_direction_output(mt9p111_gpio_keys[i].gpio,
				      mt9p111_gpio_keys[i].enabled);
		mdelay(mt9p111_gpio_keys[i].milliseconds);
	}

	return ret;
}

static int antares_mt9p111_power_off(void)
{
	int i;

	for (i = ARRAY_SIZE(mt9p111_gpio_keys) - 1; i >= 0; i--)
		gpio_direction_output(mt9p111_gpio_keys[i].gpio,
				      !mt9p111_gpio_keys[i].enabled);

	gpio_direction_output(CAM_I2C_MUX_RST_GPIO, 0);
	gpio_direction_output(CAMERA_POWER_GPIO, 0);
	return 0;
}

struct mt9p111_platform_data antares_mt9p111_data = {
	.power_on = antares_mt9p111_power_on,
	.power_off = antares_mt9p111_power_off,
};
#endif

#ifdef CONFIG_VIDEO_MT9D115
static const struct camera_gpios mt9d115_gpio_keys[] = {
	[0] = CAMERA_GPIO("en_avdd_csi", AVDD_DSI_CSI_ENB_GPIO, 1, 1),
	[1] = CAMERA_GPIO("cam_sec_pwr_dn", CAM_SEC_PWR_DN_GPIO, 0, 0),
	[2] = CAMERA_GPIO("cam_sec_rst", CAM_SEC_RST_GPIO, 1, 1),
	[3] = CAMERA_GPIO("cam_sec_rst", CAM_SEC_RST_GPIO, 0, 1),
	[4] = CAMERA_GPIO("cam_sec_rst", CAM_SEC_RST_GPIO, 1, 1),
	[5] = CAMERA_GPIO("cam_sec_ldo_en", CAM_SEC_LDO_EN_GPIO, 1, 0),
	[6] = CAMERA_GPIO("cam_sec_led", CAM_SEC_LED_GPIO, 1, 0),
};

static int antares_mt9d115_power_on(void)
{
	int i, ret = 0;

	gpio_direction_output(CAMERA_POWER_GPIO, 1);
	mdelay(1);
	gpio_direction_output(CAM_I2C_MUX_RST_GPIO, 1);
	mdelay(1);
	i2c_smbus_write_byte_data(pca9543_i2c_client, 0, 2);
	mdelay(1);
	for (i = 0; i < ARRAY_SIZE(mt9d115_gpio_keys); i++) {
		gpio_direction_output(mt9d115_gpio_keys[i].gpio,
				      mt9d115_gpio_keys[i].enabled);
		mdelay(mt9d115_gpio_keys[i].milliseconds);
	}

	return ret;
}

static int antares_mt9d115_power_off(void)
{
	int i;

	for (i = ARRAY_SIZE(mt9d115_gpio_keys) - 1; i >= 0; i--) {
		gpio_direction_output(mt9d115_gpio_keys[i].gpio,
				      !mt9d115_gpio_keys[i].enabled);
	}

	gpio_direction_output(CAM_I2C_MUX_RST_GPIO, 0);
	gpio_direction_output(CAMERA_POWER_GPIO, 0);
	return 0;
}

struct mt9d115_platform_data antares_mt9d115_data = {
	.power_on = antares_mt9d115_power_on,
	.power_off = antares_mt9d115_power_off,
};
#endif

int __init antares_camera_init(void)
{
	int i, ret = 0;
	struct regulator *cam_ldo6 = NULL;

	tegra_gpio_enable(CAMERA_POWER_GPIO);
	ret = gpio_request(CAMERA_POWER_GPIO, "cam_pwr_en");
	if (ret < 0)
		return ret;

	gpio_export(CAMERA_POWER_GPIO, false);
	gpio_direction_output(CAMERA_POWER_GPIO, 1);
	cam_ldo6 = regulator_get(NULL, "vdd_ldo6");
	if (IS_ERR_OR_NULL(cam_ldo6)) {
		pr_err("%s: Couldn't get regulator ldo6\n", __func__);
		return PTR_ERR(cam_ldo6);
	}

	ret = regulator_set_voltage(cam_ldo6, 1800 * 1000, 1800 * 1000);
	if (ret) {
		pr_err("%s: Failed to set ldo6 to 1.8v\n", __func__);
		goto fail_put_regulator;
	}

	ret = regulator_enable(cam_ldo6);
	if (ret) {
		pr_err("%s: Failed to enable ldo6\n", __func__);
		goto fail_put_regulator;
	}

	i2c_new_device(i2c_get_adapter(3), antares_i2c3_board_info_tca6416);
	ret = gpio_request(CAM_I2C_MUX_RST_GPIO, "cam_i2c_mux_rst");
	if (ret < 0)
		return ret;

	gpio_direction_output(CAM_I2C_MUX_RST_GPIO, 1);
	pca9543_i2c_client = i2c_new_device(i2c_get_adapter(3),
					    antares_i2c3_board_info_pca9543);
	for (i = 0; i < ARRAY_SIZE(mt9p111_gpio_keys); i++)
		gpio_request(mt9p111_gpio_keys[i].gpio,
			     mt9p111_gpio_keys[i].name);

	for (i = 0; i < ARRAY_SIZE(mt9d115_gpio_keys); i++)
		gpio_request(mt9d115_gpio_keys[i].gpio,
			     mt9d115_gpio_keys[i].name);

	ret = regulator_disable(cam_ldo6);
	if (ret)
		pr_err("%s: Failed to disable ldo6\n", __func__);

fail_put_regulator:
	regulator_put(cam_ldo6);
	gpio_direction_output(CAM_I2C_MUX_RST_GPIO, 0);
	gpio_direction_output(CAMERA_POWER_GPIO, 0);
	return 0;
}

static void antares_isl29018_init(void)
{
	tegra_gpio_enable(ISL29018_IRQ_GPIO);
	gpio_request(ISL29018_IRQ_GPIO, "isl29018");
	gpio_direction_input(ISL29018_IRQ_GPIO);
}

#ifdef CONFIG_SENSORS_AKM8975
static void antares_akm8975_init(void)
{
	tegra_gpio_enable(AKM8975_IRQ_GPIO);
	gpio_request(AKM8975_IRQ_GPIO, "akm8975");
	gpio_direction_input(AKM8975_IRQ_GPIO);
}
#endif

static void antares_bq20z75_init(void)
{
	tegra_gpio_enable(AC_PRESENT_GPIO);
	gpio_request(AC_PRESENT_GPIO, "ac_present");
	gpio_direction_input(AC_PRESENT_GPIO);
}

static void antares_nct1008_init(void)
{
	tegra_gpio_enable(NCT1008_THERM2_GPIO);
	gpio_request(NCT1008_THERM2_GPIO, "temp_alert");
	gpio_direction_input(NCT1008_THERM2_GPIO);
}

static struct nct1008_platform_data antares_nct1008_pdata = {
	.supported_hwrev = true,
	.ext_range = false,
	.conv_rate = 0x08,
	.offset = 0,
	.hysteresis = 0,
	.shutdown_ext_limit = NCT1008_SHUTDOWN_EXT_LIMIT, //115,
	.shutdown_local_limit = NCT1008_SHUTDOWN_LOCAL_LIMIT,
	.throttling_ext_limit = NCT1008_THROTTLE_EXT_LIMIT, //90,
	.alarm_fn = tegra_throttling_enable,
};

static const struct i2c_board_info antares_i2c0_board_info[] = {
	{
		I2C_BOARD_INFO("isl29018", 0x44),
		.irq = TEGRA_GPIO_TO_IRQ(TEGRA_GPIO_PZ2),
	},
};

static const struct i2c_board_info antares_i2c2_board_info[] = {
	{
		I2C_BOARD_INFO("bq20z75-battery", 0x0B),
		.irq = TEGRA_GPIO_TO_IRQ(AC_PRESENT_GPIO),
	},
};

static struct i2c_board_info antares_i2c4_board_info[] = {
	{
		I2C_BOARD_INFO("nct1008", 0x4C),
		.irq = TEGRA_GPIO_TO_IRQ(NCT1008_THERM2_GPIO),
		.platform_data = &antares_nct1008_pdata,
	},

#ifdef CONFIG_SENSORS_AK8975
	{
		I2C_BOARD_INFO("akm8975", 0x0C),
		.irq = TEGRA_GPIO_TO_IRQ(AKM8975_IRQ_GPIO),
	},
#endif
};

#ifdef CONFIG_VIDEO_MT9P111
static struct i2c_board_info antares_i2c6_board_info[] = {
	{
		I2C_BOARD_INFO("mt9p111", 0x3C),
		.platform_data = &antares_mt9p111_data,
	},
};
#endif

#ifdef CONFIG_VIDEO_MT9D115
static struct i2c_board_info antares_i2c7_board_info[] = {
	{
		I2C_BOARD_INFO("mt9d115", 0x3C),
		.platform_data = &antares_mt9d115_data,
	},
};
#endif

#ifdef CONFIG_MPU_SENSORS_MPU3050
#define SENSOR_MPU_NAME "mpu3050"
static struct mpu3050_platform_data mpu3050_data = {
	.int_config  = 0x10,
	.orientation = {  0,  1,  0,
			  1,  0,  0,
			  0,  0,  -1 },  /* Orientation matrix for MPU on antares */
	.level_shifter = 0,
	.accel = {
#ifdef CONFIG_MPU_SENSORS_KXTF9
	.get_slave_descr = get_accel_slave_descr,
	.irq = TEGRA_GPIO_TO_IRQ(TEGRA_GPIO_PN4),
#else
	.get_slave_descr = NULL,
#endif
	.adapt_num   = 0,
	.bus         = EXT_SLAVE_BUS_SECONDARY,
	.address     = 0x0F,
    .orientation = {   -1,  0,  0,
                       0,  1,  0,
                       0,  0,  -1 },  /* Orientation matrix for Accel on antares */
	},

	.compass = {
#ifdef CONFIG_MPU_SENSORS_AK8975
	.get_slave_descr = get_compass_slave_descr,
	.irq = TEGRA_GPIO_TO_IRQ(TEGRA_GPIO_PN5),
#else
	.get_slave_descr = NULL,
#endif
	.adapt_num   = 4,            /* bus number 4 on antares */
	.bus         = EXT_SLAVE_BUS_PRIMARY,
	.address     = 0x0C,
	.orientation = {  1,  0,  0,
			  0, -1,  0,
			  0,  0, -1 },  /* Orientation matrix for AKM on antares */
	},
};

static struct i2c_board_info __initdata mpu3050_i2c0_boardinfo[] = {
	{
		I2C_BOARD_INFO(SENSOR_MPU_NAME, 0x68),
		.irq = TEGRA_GPIO_TO_IRQ(TEGRA_GPIO_PZ4),
		.platform_data = &mpu3050_data,
	},
};

static void antares_mpuirq_init(void)
{
	pr_info("*** MPU START *** antares_mpuirq_init...\n");
	tegra_gpio_enable(TEGRA_GPIO_PZ4);
	gpio_request(TEGRA_GPIO_PZ4, SENSOR_MPU_NAME);
	gpio_direction_input(TEGRA_GPIO_PZ4);
	tegra_gpio_enable(TEGRA_GPIO_PN4);
	gpio_request(TEGRA_GPIO_PN4, "KXTF9");
	gpio_direction_input(TEGRA_GPIO_PN4);
	pr_info("*** MPU END *** antares_mpuirq_init...\n");
}
#endif

#ifdef CONFIG_INPUT_MICROCHIP_I2C
static struct microchip_i2c_data microchip_data = {
	.gpio_off = TEGRA_GPIO_PW1,
};

static const struct i2c_board_info antares_i2c4_microchip_info[] = {
	{
		I2C_BOARD_INFO("microchip_i2c", 0x43),
		.irq = TEGRA_GPIO_TO_IRQ(TEGRA_GPIO_PG0),
		.platform_data = &microchip_data,
	},
};

static int __init antares_microchip_init(void)
{
	tegra_gpio_enable(TEGRA_GPIO_PG0);
	tegra_gpio_enable(TEGRA_GPIO_PW1);

	tegra_gpio_enable(TEGRA_GPIO_PR0);
	gpio_request(TEGRA_GPIO_PR0, "CAP_OFF_ER2");
	gpio_direction_output(TEGRA_GPIO_PR0, 0);

	i2c_register_board_info(4, antares_i2c4_microchip_info, 1);

	return 0;
}
#endif
#if 0
static void check_accel_rotation ( void )
{
// orient_table: index 0-0 degree, 1-90 deg, 2-180 deg, 3-270 deg
// this table is used to replace orientation field in accel of mpu_data
// according to SENSORS_KXTF9_HWROTATION
    signed char orient_table[4][9] = {
        {  -1,  0,  0,  0,  1,  0,  0,  0, -1   },
        {   0, -1,  0, -1,  0,  0,  0,  0, -1   },
        {   1,  0,  0,  0, -1,  0,  0,  0, -1   },
        {   0,  1,  0,  1,  0,  0,  0,  0, -1   },
    };
    signed char * pc1, * pc2;
    int hwr = SENSORS_KXTF9_HWROTATION;
    int index;

//    pr_db ( "VV_DBG --- %s: check_accel_rotation IN *****\n", __FUNCTION__ );
    index = hwr / 90;
    if ( index < 0 || index > 3 ) return;
    pc1 = orient_table [index];
    pc2 = mpu3050_data.accel.orientation;
    memcpy ( pc2, pc1, sizeof(signed char)*9 );
//    pr_db( "VV_DBG --- %s: check_accel_rotation[%d] *****\n", __FUNCTION__, hwr );
}
#endif
int __init antares_sensors_init(void)
{
	struct board_info BoardInfo;
        //check_accel_rotation ();
	antares_isl29018_init();
#ifdef CONFIG_SENSORS_AK8975
	antares_akm8975_init();
#endif
#ifdef CONFIG_MPU_SENSORS_MPU3050
	antares_mpuirq_init();
#endif

	antares_nct1008_init();

	i2c_register_board_info(0, antares_i2c0_board_info,
		ARRAY_SIZE(antares_i2c0_board_info));

	tegra_get_board_info(&BoardInfo);

	/*
	 * battery driver is supported on FAB.D boards and above only,
	 * since they have the necessary hardware rework
	 */
	if (BoardInfo.sku > 0) {
		antares_bq20z75_init();
		i2c_register_board_info(2, antares_i2c2_board_info,
			ARRAY_SIZE(antares_i2c2_board_info));
	}

	i2c_register_board_info(4, antares_i2c4_board_info,
		ARRAY_SIZE(antares_i2c4_board_info));

#ifdef CONFIG_VIDEO_MT9P111
	i2c_register_board_info(6, antares_i2c6_board_info,
		ARRAY_SIZE(antares_i2c6_board_info));
#endif

#ifdef CONFIG_VIDEO_MT9D115
	i2c_register_board_info(7, antares_i2c7_board_info,
		ARRAY_SIZE(antares_i2c7_board_info));
#endif

#ifdef CONFIG_MPU_SENSORS_MPU3050
	i2c_register_board_info(0, mpu3050_i2c0_boardinfo,
		ARRAY_SIZE(mpu3050_i2c0_boardinfo));
#endif

#ifdef CONFIG_INPUT_MICROCHIP_I2C
	antares_microchip_init();
#endif

	return 0;
}

late_initcall(antares_camera_init);
