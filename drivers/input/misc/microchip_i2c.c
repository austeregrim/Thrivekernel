#include <linux/module.h>
#include <linux/input.h>
#include <linux/i2c.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/earlysuspend.h>
#include <linux/freezer.h>
#include <linux/interrupt.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/poll.h>
#include <linux/kfifo.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include <linux/gpio.h>
#include <linux/slab.h>
#include <linux/i2c/microchip_i2c.h>

#define MICROCHIP_DEBUG 0
#define MICROCHIP_IDLE	0

#define DRIVER_NAME	"microchip_i2c"

#define BUTTONS_STATUS_REG      0x00
#define BUTTONS_CHANGE_REG      0x01
#define LED_STATUS_REG          0x02
#define LED_ONOFF_REG           0x03
#define LED_BLINK_REG           0x04
#define WAKEUP_REG              0x05
#define LED_CTRL_REG            0x06
#define CHIP_ID_REG             0x07
#define INT_REG                 0x08
#define PCTRL_REG               0x09
#define FW_REV0_REG             0x0a
#define FW_REV1_REG             0x0b
#define FW_REV2_REG             0x0c
#define LED_MANUAL_MODE_REG     0x0d
#define LED_BLINK_FREQ_REG      0x0e
#define LED_BLINK_DUTY_REG      0x0f
#define LED_SET_T1_REG          0x10
#define LED_SET_T2_REG          0x11
#define LED_SET_T3_REG          0x12
#define BTN0_SENSITIVITY_REG    0x13
#define BTN1_SENSITIVITY_REG    0x14
#define BTN2_SENSITIVITY_REG    0x15
#define BTN3_SENSITIVITY_REG    0x16
#define BTN4_SENSITIVITY_REG    0x17
#define BTN5_SENSITIVITY_REG    0x18
#define BTN6_SENSITIVITY_REG    0x19
#define BTN7_SENSITIVITY_REG    0x1a

struct microchip_i2c_driver_data
{
	struct i2c_client	    *client;
	struct task_struct	    *task;
	struct input_dev	    *input_dev;
	struct semaphore        sem;
	struct early_suspend    early_suspend;
	int			            sensitivity;
	int			            chip_devinfo;
	bool			        bThreadAlive;
};

static bool status = true;

enum cap_sensor_key {
	CAP_KEY_SEARCH  = 0x08,
	CAP_KEY_BACK    = 0x10,
	CAP_KEY_HOME    = 0x20,
	CAP_KEY_MENU    = 0x80,
};

static int microchip_i2c_read(struct i2c_client *client, char *pbuf)
{
	return i2c_master_recv(client, pbuf, 1);
}

static int microchip_i2c_write(struct i2c_client *client, const char *pbuf, int count)
{
	return i2c_master_send(client, pbuf, count);
}

static int microchip_register_read(struct i2c_client *client, u8 addr, char *pbuf)
{
	if(1 != microchip_i2c_write(client, &addr, 1))
		return -1;
	else if(1 != microchip_i2c_read(client, pbuf))
		return -1;
	else
		return 0;
}

#if MICROCHIP_IDLE
static int microchip_register_write(struct i2c_client *client, u8 addr, char value)
{
	char cBuf[2];

	cBuf[0] = addr;
	cBuf[1] = value;
	if(2 != microchip_i2c_write(client, cBuf, 2))
		return -1;
	else
		return 0;
}
#endif

static irqreturn_t microchip_i2c_interrupt(int irq, void *dev_id)
{
	struct microchip_i2c_driver_data *capsensor = (struct microchip_i2c_driver_data*)dev_id;

	up(&capsensor->sem);

	return IRQ_HANDLED;
}

static int microchip_i2c_thread (void *pdata)
{
	struct microchip_i2c_driver_data *capsensor = (struct microchip_i2c_driver_data*)pdata;
	char ButtonChange = 0, ButtonStatus = 0;
	short KeyReportFlag = 0;
	int key_pressed = 0;

	capsensor->bThreadAlive = 1;
	while (capsensor->bThreadAlive) {

		down(&capsensor->sem);

		microchip_register_read(capsensor->client, BUTTONS_CHANGE_REG, &ButtonChange);
		microchip_register_read(capsensor->client, BUTTONS_STATUS_REG, &ButtonStatus);

		#if 1
		if((ButtonChange==ButtonStatus) || (ButtonStatus==(CAP_KEY_SEARCH|CAP_KEY_MENU))) {
			key_pressed = 1;
		} else if((ButtonStatus==0) || (ButtonChange!=ButtonStatus)) {
		    key_pressed = 0;
		}

        if(ButtonChange & CAP_KEY_SEARCH) {
			if((ButtonStatus==(CAP_KEY_SEARCH|CAP_KEY_MENU)) && (ButtonChange==CAP_KEY_SEARCH)) {
				ButtonChange = CAP_KEY_MENU;
			}
			if((ButtonChange==(CAP_KEY_SEARCH|CAP_KEY_MENU)) && (ButtonStatus==CAP_KEY_MENU)) {
				ButtonChange = CAP_KEY_SEARCH;
			}
        }

		if(key_pressed == 0) {
			if((ButtonChange==(CAP_KEY_SEARCH|CAP_KEY_MENU)) && (ButtonStatus==CAP_KEY_MENU)) {
				ButtonChange = CAP_KEY_SEARCH;
			}
			if((ButtonChange==(CAP_KEY_SEARCH|CAP_KEY_MENU)) && (ButtonStatus==CAP_KEY_SEARCH)) {
				ButtonChange = CAP_KEY_MENU;
			}
		}
		#endif

		if(key_pressed) {
			if(KeyReportFlag & ButtonChange)
				continue;
		} else {
			if(ButtonChange != (KeyReportFlag & ButtonChange))
				continue;
		}

	    switch(ButtonChange) {
			case CAP_KEY_SEARCH:
				input_report_key(capsensor->input_dev, KEY_SEARCH, key_pressed);
				break;
			case CAP_KEY_BACK:
				input_report_key(capsensor->input_dev, KEY_BACK, key_pressed);
				break;
			case CAP_KEY_HOME:
				input_report_key(capsensor->input_dev, KEY_HOME, key_pressed);
				break;
			case CAP_KEY_MENU:
				input_report_key(capsensor->input_dev, KEY_MENU, key_pressed);
				break;
			default:
				#if MICROCHIP_DEBUG
					printk("Invalid Key Code: 0x%x\n", ButtonChange);
				#endif
				continue;
		}

		if(key_pressed) {
			KeyReportFlag |= ButtonChange;
		} else {
			KeyReportFlag &= (~ButtonChange);
			#if MICROCHIP_IDLE
			microchip_register_write(capsensor->client, PCTRL_REG, 0x01);
			#endif
		}

		#if MICROCHIP_DEBUG
			printk(">>>> key_pressed = %d Button Change = 0x%x Button Status = 0x%x\n",
					key_pressed, ButtonChange, ButtonStatus);
		#endif
	}

	return 0;
}

#ifdef CONFIG_HAS_EARLYSUSPEND
static void microchip_i2c_early_suspend(struct early_suspend *es)
{
	struct microchip_i2c_driver_data *capsensor = container_of(es, struct microchip_i2c_driver_data, early_suspend);
	struct microchip_i2c_data *pdata = capsensor->client->dev.platform_data;

	gpio_direction_output(pdata->gpio_off, 1);
}

static void microchip_i2c_early_resume(struct early_suspend *es)
{
	struct microchip_i2c_driver_data *capsensor = container_of(es, struct microchip_i2c_driver_data, early_suspend);
	struct microchip_i2c_data *pdata = capsensor->client->dev.platform_data;

	if(status){
		gpio_direction_output(pdata->gpio_off, 0);
		msleep(100);
	}
}
#endif

ssize_t microchip_i2c_info_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	unsigned char CapID, CapFwRev0, CapFwRev1, CapFwRev2;

	microchip_register_read(client, CHIP_ID_REG, &CapID);
	microchip_register_read(client, FW_REV2_REG, &CapFwRev2);
	microchip_register_read(client, FW_REV1_REG, &CapFwRev1);
	microchip_register_read(client, FW_REV0_REG, &CapFwRev0);

	sprintf(buf, "Capacitive Sensor ID = 0x%02X, FW Rev = 0x%02X%02X%02X\n", CapID, CapFwRev2, CapFwRev1, CapFwRev0);
	return strlen(buf);
}

DEVICE_ATTR(info, S_IRUGO, microchip_i2c_info_show, NULL);

ssize_t microchip_i2c_enable_set(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t len)
{
	struct i2c_client *client = container_of(dev, struct i2c_client, dev);
	struct microchip_i2c_data *pdata = client->dev.platform_data;

	if(len < 1){
		return -EINVAL;
	}

	if(strnicmp(buf, "on", 2) == 0){//resume
		gpio_direction_output(pdata->gpio_off, 0);
		status = true;
	}
	else if(strnicmp(buf, "off", 3) == 0){//suspend
		gpio_direction_output(pdata->gpio_off,1);
		status = false;
	}

	return len;
}

ssize_t microchip_i2c_enable_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	sprintf(buf, "%s\n", status ? "on" : "off");
	return strlen(buf);
}

DEVICE_ATTR(enable, S_IWUGO | S_IRUGO, microchip_i2c_enable_show, microchip_i2c_enable_set);

static int __devinit microchip_i2c_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct microchip_i2c_data *pdata = client->dev.platform_data;
	struct microchip_i2c_driver_data *capsensor = NULL;
	struct input_dev *input_dev = NULL;
	char CapID, CapFwRev0, CapFwRev1, CapFwRev2;
	int err;

	capsensor = kzalloc(sizeof(*capsensor), GFP_KERNEL);
	if (capsensor == NULL) {
		err = -ENOMEM;
		pr_err("%s: failed to allocate driver data\n", __FUNCTION__);
		goto allocate_dev_fail;
	}

	i2c_set_clientdata(client, capsensor);
	capsensor->client = client;

	err = gpio_request(pdata->gpio_off, "microchip_off");
	if (err < 0) {
		pr_err("%s: failed to request GPIO %d,"
			" error %d\n", __FUNCTION__, irq_to_gpio(client->irq), err);
		goto allocate_dev_fail;
	}
	err = gpio_direction_output(pdata->gpio_off, 0);
	if (err < 0) {
		pr_err("%s: failed to configure input"
			" direction for GPIO %d, error %d\n",
			__FUNCTION__, irq_to_gpio(client->irq), err);
		goto off_gpio_fail;
	}
	msleep(100);

	err = microchip_register_read(client, CHIP_ID_REG, &CapID);
	if (err < 0) {
		pr_err("%s: controller probe failed\n", __FUNCTION__);
		goto off_gpio_fail;
	}
	microchip_register_read(client, FW_REV2_REG, &CapFwRev2);
	microchip_register_read(client, FW_REV1_REG, &CapFwRev1);
	microchip_register_read(client, FW_REV0_REG, &CapFwRev0);
	#if MICROCHIP_IDLE
	microchip_register_write(client, WAKEUP_REG, 0xB8);
	microchip_register_write(client, PCTRL_REG, 0x01);
	#endif

	err = gpio_request(irq_to_gpio(client->irq), client->name);
	if (err < 0) {
		pr_err("%s: failed to request GPIO %d,"
			" error %d\n", __FUNCTION__, irq_to_gpio(client->irq), err);
		goto off_gpio_fail;
	}
	err = gpio_direction_input(irq_to_gpio(client->irq));
	if (err < 0) {
		pr_err("%s: failed to configure input"
			" direction for GPIO %d, error %d\n",
			__FUNCTION__, irq_to_gpio(client->irq), err);
		goto irq_gpio_fail;
	}

	sema_init(&capsensor->sem, 0);
	capsensor->task = kthread_create(microchip_i2c_thread,
		capsensor, "microchip_i2c_thread");
	if (capsensor->task == NULL) {
		err = -1;
		goto thread_create_failed;
	}
    wake_up_process(capsensor->task);

	input_dev = input_allocate_device();
	if (input_dev == NULL) {
		err = -ENOMEM;
		pr_err("%s: Failed to allocate input device\n", __FUNCTION__);
		goto allocate_dev_fail;
	}
	capsensor->input_dev = input_dev;
	capsensor->input_dev->name = "Microchip Capacitive sensor";
	capsensor->input_dev->dev.parent = &client->dev;
	input_set_drvdata(capsensor->input_dev, capsensor);

	set_bit(EV_KEY, capsensor->input_dev->evbit);
	set_bit(KEY_SEARCH, input_dev->keybit);
	set_bit(KEY_HOME, input_dev->keybit);
	set_bit(KEY_MENU, input_dev->keybit);
	set_bit(KEY_BACK, input_dev->keybit);

	err = input_register_device(input_dev);
	if (err) {
		pr_err("%s: Unable to register input device\n", __FUNCTION__);
		goto input_register_device_failed;
	}

	err = device_create_file(&client->dev, &dev_attr_info);
	if (err) {
		pr_err("tegra_cap_probe: add_sysfs_entry info failed\n");
		goto input_register_device_failed;
	}

	err = device_create_file(&client->dev, &dev_attr_enable);
	if (err) {
		pr_err("tegra_cap_probe: add_sysfs_entry enable failed\n");
		goto input_register_device_failed;
	}

	dev_set_drvdata(&client->dev, capsensor);

	#ifdef CONFIG_HAS_EARLYSUSPEND
	capsensor->early_suspend.suspend = microchip_i2c_early_suspend;
	capsensor->early_suspend.resume  = microchip_i2c_early_resume;
	register_early_suspend(&capsensor->early_suspend);
	#endif

	err = request_irq(client->irq, microchip_i2c_interrupt, IRQF_DISABLED | IRQF_TRIGGER_RISING,
			  client->name, capsensor);
	if (err) {
		pr_err("%s: Unable to request capacitive sensor IRQ.\n", __FUNCTION__);
		goto sysfs_failed;
	}

	printk(KERN_INFO "%s ID = 0x%02X, FW Rev = 0x%02X%02X%02X successfully registered\n", input_dev->name, CapID, CapFwRev2, CapFwRev1, CapFwRev0);
	return err;

sysfs_failed:
	input_unregister_device(input_dev);
input_register_device_failed:
	input_free_device(input_dev);
	capsensor->bThreadAlive = 0;
thread_create_failed:
	kthread_stop(capsensor->task);
irq_gpio_fail:
	gpio_free(irq_to_gpio(client->irq));
off_gpio_fail:
	gpio_free(pdata->gpio_off);
allocate_dev_fail:
	kfree(capsensor);
	err = -ENOMEM;

	return err;
}

static int __devexit microchip_i2c_remove(struct i2c_client *client)
{
	struct microchip_i2c_driver_data *capsensor = i2c_get_clientdata(client);
	struct microchip_i2c_data *pdata = client->dev.platform_data;

	#ifdef CONFIG_HAS_EARLYSUSPEND
	unregister_early_suspend(&capsensor->early_suspend);
	#endif
	capsensor->bThreadAlive = 0;
	//remove_sysfs_entry_capsensor(pdev);
	gpio_free(pdata->gpio_off);
	free_irq(client->irq, capsensor);
	gpio_free(irq_to_gpio(client->irq));
	input_unregister_device(capsensor->input_dev);
	return 0;
}

static const struct i2c_device_id microchip_i2c_id[] = {
	{ DRIVER_NAME, 0 },
	{ }
};

static struct i2c_driver microchip_i2c_driver = {
    .probe   = microchip_i2c_probe,
    .remove  = microchip_i2c_remove,

#ifndef CONFIG_HAS_EARLYSUSPEND
    .suspend = microchip_i2c_suspend,
    .resume  = microchip_i2c_resume,
#endif
	.id_table	= microchip_i2c_id,
    .driver  = {
        .name   = DRIVER_NAME,
    },
};

static int __init microchip_i2c_init(void) {
    int e;

	e = i2c_add_driver(&microchip_i2c_driver);
	if (e != 0) {
		pr_err("%s: failed to register with I2C bus with "
		       "error: 0x%x\n", __func__, e);
	}
	return e;
}

static void __exit microchip_i2c_exit(void) {

    i2c_del_driver(&microchip_i2c_driver);
}

module_init(microchip_i2c_init);
module_exit(microchip_i2c_exit);

MODULE_DESCRIPTION("Microchip I2C capacitive sensor driver");

