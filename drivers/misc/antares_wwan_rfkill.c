/*
 * Antares WWAN rfkill power control via GPIO
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/gpio.h>
#include <linux/rfkill.h>
#include <linux/delay.h>
#include <linux/regulator/consumer.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

struct antares_rfkill_dev {
    struct rfkill *wwan_rfkill;
    struct rfkill *gps_rfkill;
    spinlock_t lock;
    int disable_pin;
    int wwan_rfkill_state;
    int gps_rfkill_state;
};

static void power_on(struct antares_rfkill_dev *dev, int onoff)
{
    if (onoff)
        gpio_set_value(dev->disable_pin, 1);
    else
        gpio_set_value(dev->disable_pin, 0);
}

static int wwan_rfkill_set_block(void *data, bool blocked)
{
    struct antares_rfkill_dev *dev = (struct antares_rfkill_dev *)data;
    unsigned long flags;

    spin_lock_irqsave(&dev->lock, flags);
    dev->wwan_rfkill_state = !blocked;

    if (!blocked) {             /* Enable WWAN */
        power_on(dev, 1);
    } else {                    /* Disable WWAN */
        if (dev->gps_rfkill_state == 0)
            power_on(dev, 0);
    }

    spin_unlock_irqrestore(&dev->lock, flags);
	return 0;
}

static int gps_rfkill_set_block(void *data, bool blocked)
{
    struct antares_rfkill_dev *dev = (struct antares_rfkill_dev *)data;
    unsigned long flags;

    spin_lock_irqsave(&dev->lock, flags);
    dev->gps_rfkill_state = !blocked;

    if (!blocked) {             /* Enable GPS */
        power_on(dev, 1);
    } else {                    /* Disable GPS */
        if (dev->wwan_rfkill_state == 0)
            power_on(dev, 0);
    }
    
    spin_unlock_irqrestore(&dev->lock, flags);
    return 0;
}

static struct rfkill_ops wwan_rfkill_ops = {
	.set_block = wwan_rfkill_set_block,
};

static struct rfkill_ops gps_rfkill_ops = {
    .set_block = gps_rfkill_set_block,
};

static int antares_rfkill_probe(struct platform_device *pdev)
{
    struct antares_rfkill_dev *dev = NULL;
    struct resource *res;

	int rc = -EINVAL;

    dev = kzalloc(sizeof(struct antares_rfkill_dev), GFP_KERNEL);
    if (!dev)
        return rc;

    res = platform_get_resource_byname(pdev, IORESOURCE_IO, 
                                       "wwan_disable_gpio");
    if (res) {
        dev->disable_pin = res->start;
        tegra_gpio_enable(dev->disable_pin);
        rc = gpio_request(dev->disable_pin, "wwan_disable");
        if (rc < 0) {
            printk(KERN_ERR "antares_wwan_rfkill: Can't request gpio\n");
            goto fail_gpio_request;
        }
    } else {
        printk(KERN_ERR "antares_wwan_rfkill: Can't get IO resource\n");
        kfree(dev);
        return -ENODEV;
    }
    
    spin_lock_init(&dev->lock);

	dev->wwan_rfkill = rfkill_alloc("antares-rfkill", &pdev->dev,
                                    RFKILL_TYPE_WWAN, &wwan_rfkill_ops, dev);
	if (!dev->wwan_rfkill) {
		rc = -ENOMEM;
		goto fail_rfkill_alloc;
	}

    dev->gps_rfkill = rfkill_alloc("antares-rfkill", &pdev->dev,
                                   RFKILL_TYPE_GPS, &gps_rfkill_ops, dev);
    if (!dev->gps_rfkill) {
        rc = -ENOMEM;
        goto fail_rfkill_alloc;
    }

	// setup init state
	// on-line when system (re)start
    dev->wwan_rfkill_state = 0;
    dev->gps_rfkill_state = 0;
    rfkill_init_sw_state(dev->wwan_rfkill, true);			// RF is not blocked
    rfkill_init_sw_state(dev->gps_rfkill, true);

    gpio_direction_output(dev->disable_pin, 0); /* power off module */

	// set platform data address
	platform_set_drvdata(pdev, dev);
	
	// register rfkill path in sysfs
	rc = rfkill_register(dev->wwan_rfkill);
	if (rc < 0)
		goto fail_rfkill_reg;

    rc = rfkill_register(dev->gps_rfkill);
    if (rc < 0)
        goto fail_rfkill_reg;

    printk(KERN_INFO "antares_wwan_rfkill: WWAN & GPS rfkill driver registered\n");

	return 0;

 fail_rfkill_reg:
    if (dev->wwan_rfkill) {
        rfkill_unregister(dev->wwan_rfkill);
    }

    if (dev->gps_rfkill) {
        rfkill_unregister(dev->gps_rfkill);
    }
 fail_rfkill_alloc:
    gpio_free(dev->disable_pin);
    if (dev->wwan_rfkill)
        rfkill_destroy(dev->wwan_rfkill);
    if (dev->gps_rfkill)
        rfkill_destroy(dev->gps_rfkill);
	
 fail_gpio_request:
    kfree(dev);
	return rc;
}



static int antares_rfkill_remove(struct platform_device *pdev)
{
	struct antares_rfkill_dev *dev = platform_get_drvdata(pdev);

	rfkill_unregister(dev->wwan_rfkill);
	rfkill_destroy(dev->wwan_rfkill);

    rfkill_unregister(dev->gps_rfkill);
    rfkill_destroy(dev->gps_rfkill);

	gpio_free(dev->disable_pin);
    
    kfree(dev);

	return 0;
}

static void antares_rfkill_shutdown(struct platform_device *pdev)
{
    struct antares_rfkill_dev *dev = platform_get_drvdata(pdev);

    power_on(dev, 0);
}

static struct platform_driver antares_rfkill_driver = {
	.probe = antares_rfkill_probe,
	.remove = antares_rfkill_remove,
    .shutdown = antares_rfkill_shutdown,
	.driver = {
		.name = "antares_wwan_rfkill",
		.owner = THIS_MODULE,
	},
};

static int __init antares_wwan_rfkill_init(void)
{
	return platform_driver_register(&antares_rfkill_driver);
}

static void __exit antares_wwan_rfkill_exit(void)
{
	platform_driver_unregister(&antares_rfkill_driver);
}

module_init(antares_wwan_rfkill_init);
module_exit(antares_wwan_rfkill_exit);

MODULE_DESCRIPTION("Antares WWAN RFKILL driver");
MODULE_AUTHOR("Ron Lee <ron1_lee@pegatroncorp.com>");
MODULE_LICENSE("GPL");
