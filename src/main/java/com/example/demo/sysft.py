from apollo_libs import lib
from . import cw9162df_test_steps as cw9162


def cw9162_sysft_main_sequence_definition():
    """
    :return: seq
    """
    seq = lib.get_sequence_definition("SYSFT Main Sequence")
    seq.add_step(cw9162.first_step_of_main_seq, name="First Step of Main")
    seq.add_step(cw9162.initialize_connection, name="Initialize Connection")
    seq.add_step(cw9162.initialize_variables, name="Initialize Variables")
    seq.add_step(cw9162.initialize_variables_df, name="Initialize Variables for DF")

    uboot1_sub_seq = seq.add_sequence(name="UBOOT1", loop_on_error=1)
    uboot1_sub_seq.add_step(cw9162.poe_port_power_off, name="POE Power OFF 1", loop_on_error=1)
    uboot1_sub_seq.add_step(cw9162.poe_port_power_on, name="POE Power ON 1", loop_on_error=1)
    uboot1_sub_seq.add_step(
        cw9162.get_uboot_prompt,
        name="Get U-Boot prompt 1",
        kwargs=dict(show_version=True),
    )
    uboot1_sub_seq.add_step(cw9162.set_default_env, name="Set Default Environment1")
    uboot1_sub_seq.add_step(
        cw9162.set_tftp_env,
        name="Set TFTP environment1",
        kwargs=dict(reset_enable=False),
    )
    uboot1_sub_seq.add_step(cw9162.ping_tftp_server, name="Ping TFTP server1")
    uboot1_sub_seq.add_step(cw9162.boot_mfg_image, name="Boot MFG image")
    uboot1_sub_seq.add_step(cw9162.mfg_version_check, name="Check MFG image version")

    mfg_sub_seq = seq.add_sequence(name="MFG IMAGE")
    mfg_sub_seq.add_step(cw9162.mfg_read_cookie_all, name="Read cookie 1")
    mfg_sub_seq.add_step(cw9162.verify_pca_sn_pn_rev, name="Check PCA SN and part number")
    mfg_sub_seq.add_step(cw9162.verify_cookie_mac, name="Verify MAC address in cookie")
    mfg_sub_seq.add_step(cw9162.verify_pid_vid, name="Verify PIDVID")
    mfg_sub_seq.add_step(cw9162.mfg_prog_cookie, name="Program cookies")
    mfg_sub_seq.add_step(cw9162.mfg_read_cookie_all, name="Read cookie 2")
    mfg_sub_seq.add_step(cw9162.verify_cookie, name="Verify cookie")
    mfg_sub_seq.add_step(cw9162.verify_radio_carrier_cmpd, name="Verify radio carrier")
    mfg_sub_seq.add_step(cw9162.validate_act2_installation, name="ACT2 validation")
    mfg_sub_seq.add_step(cw9162.verify_x509_installation, name="X509 validation")
    mfg_sub_seq.add_step(cw9162.mfg_reboot, name="Reboot in MFG")

    uboot2_sub_seq = seq.add_sequence(name="UBOOT2")
    uboot2_sub_seq.add_step(cw9162.get_uboot_prompt, name="Get U-Boot prompt 2")
    uboot2_sub_seq.add_step(cw9162.set_tftp_env, name="Set TFTP environment2")
    uboot2_sub_seq.add_step(cw9162.ping_tftp_server, name="Ping TFTP server2")
    uboot2_sub_seq.add_step(cw9162.tftp_customer_image, name="TFTP customer image")
    uboot2_sub_seq.add_step(cw9162.set_default_env, name="Set Default Environment2")
    uboot2_sub_seq.add_step(cw9162.uboot_reset, name="Reset UUT in UBOOT")

    customer_sub_seq = seq.add_sequence(name="CUSTOMER IMAGE")
    customer_sub_seq.add_step(cw9162.boot_customer_image, name="Boot customer image")
    customer_sub_seq.add_step(cw9162.customer_version_check, name="Check customer image version")
    customer_sub_seq.add_step(cw9162.customer_image_ping, name="Customer image ping test")
    customer_sub_seq.add_step(cw9162.customer_capwap_erase, name="Erase capwap config")

    powercycle_sub_seq = seq.add_sequence(name="POWER CYCLE")
    powercycle_sub_seq.add_step(cw9162.poe_port_power_off, name="POE Power OFF 2", loop_on_error=1)
    powercycle_sub_seq.add_step(cw9162.poe_port_power_on, name="POE Power ON 2", loop_on_error=1)
    powercycle_sub_seq.add_step(cw9162.verify_ap_mode_secureboot, name="Verify AP mode and secureboot")
    powercycle_sub_seq.add_step(cw9162.boot_customer_image, name="Boot customer image 2")
    powercycle_sub_seq.add_step(cw9162.customer_capwap_erase, name="Clear config and reload")
    powercycle_sub_seq.add_step(
        cw9162.get_uboot_prompt,
        name="Get U-Boot prompt 4",
        kwargs=dict(show_version=True),
    )
    powercycle_sub_seq.add_step(
        cw9162.set_default_env,
        name="Set Default Environment3",
        kwargs=dict(check_env=True),
    )

    seq.add_step(cw9162.verify_rohs, name="Verify ROHS")
    seq.add_step(cw9162.finalization, name="Finalization", finalization=True)

    return seq
