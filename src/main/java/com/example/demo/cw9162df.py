import logging
import time
from datetime import datetime, timedelta
from apollo_libs import lib, cesiumlib
from .....libs import decorator, utilities, definition
from .. import cw9162

log = logging.getLogger(__name__)


class CW9162Df(cw9162.CW9162):
    """
    product site level class for CW9162 DF test
    """

    @decorator.log_handler2
    def initialize_variables_df(self):
        """
        Initialize the variable that DF need to use
        :return:
        """
        if self.test_station[:3] in [
            "FJZ",
            "fjz",
            "SZN",
            "szn",
            "CIS",
            "cis",
            "FXG",
            "fxg",
        ]:
            self.eco_current = self.EA599701
            self.eco_previous = self.EA599701

        self.mfg_image = self.MFG_IMAGE_NAME

        if not isinstance(self.eco_current, dict):
            self.go_to_failure("self.eco_current is not set correctly, NOT a dictionary!")
        return lib.PASS

    @decorator.log_handler2
    def verify_cookie_mac(self):
        """
        Verify PCA MAC address and blocksize in cookies against what Cesium has record at ASSY
        test step of mfg_read_cookie_all should run to set self.cookie_dict[MAC Address] and [MAC Address Block Size]
        :return:
        """

        self.mac_block_size = int(self.cookie_dict["MAC Address Block Size"])
        log.debug(
            "partnumber_74=[{}], mac_address=[{}], mac_blocksize=[{}]".format(
                self.partnum_74, self.mac_address, self.mac_block_size
            )
        )
        # self.mac_address is set in the pre-sequence while scanning QR label
        if self.mac_address != self.cookie_dict["MAC Address"].replace(":", ""):
            log.debug("Mac address on QR label = [{}]".format(self.mac_address))
            log.debug("Mac address in cookie   = [{}]".format(self.cookie_dict["MAC Address"].replace(":", "")))
            self.go_to_failure("Mac address in cookie mismatch QR label")
        if self.mac_block_size != self.ETH_MAC_BLOCK_SIZE:
            self.go_to_failure("mac block size in cookie mismatch the definition of ETH_MAC_BLOCK_SIZE")
        if int(self.cookie_dict["Radio 0 MAC Address Block Size"]) != self.RADIO_MAC_BLOCK_SIZE:
            self.go_to_failure("Radio mac block size in cookie mismatch the definition of RADIO_MAC_BLOCK_SIZE")
        self.verify_mb_mac()

        return lib.PASS

    @decorator.log_handler2
    def verify_pid_vid(self):
        """
        Call cesiumlib function to data from PIDVID table, and compare it with ECO definition.
        Achieve basepid from PIDVID table
        :return: lib.PASS
        """

        self.tan = self.eco_current[self.uuttype]["tan"]
        self.tan_revision = self.eco_current[self.uuttype]["tan_rev"]
        if "SYSFT" in self.area:
            # self.vid is set in pre-sequence in QR label scanning for SYSFT
            if self.vid != self.eco_current[self.uuttype]["vid"]:
                self.go_to_failure(
                    "VID [{}] on QR label mismatch ECO definition [{}]".format(
                        self.vid, self.eco_current[self.uuttype]["vid"]
                    )
                )
        else:
            self.vid = self.eco_current[self.uuttype]["vid"]
        pidvid = cesiumlib.get_vid(self.tan, self.uuttype)  # get PID VID from PIDVID table
        log.debug("pidvid table={}".format(pidvid))
        log.debug("eco_definition={}".format(self.eco_current[self.uuttype]))
        if pidvid["vid"] != self.vid:
            self.go_to_failure("VID in PIDVID table:[{}] mismatch ECO.VID:[{}]".format(pidvid["vid"], self.vid))

        self.basepid = cesiumlib.get_base_pid(self.tan, self.uuttype)["base_pid"]
        log.debug("self.basepid = [{}]".format(self.basepid))

        return lib.PASS

    def verify_pca_pn(self):
        """
        Verify PCA assemble part number against ECO definition
        :return:
        """
        scanned_pca_pn = self.partnum_74
        log.debug("pca_pn in ECO definition = [{}]".format(self.eco_current[self.uuttype]["pca_pn"]))
        log.debug("pca_pn in scan           = [{}]".format(scanned_pca_pn))
        if scanned_pca_pn != self.eco_current[self.uuttype]["pca_pn"]:
            self.go_to_failure("pca_pn in ECO definition mistmatch pca_pn in scan!!")

        return lib.PASS

    @decorator.log_handler2
    def record_mb_mac(self):
        """
        Verify if MAC addres already exist in database, if not, record it using cesiumlib
        self.partnum_74 and self.mac_address are set in scan_info test step from QR code
        :return:
        """
        mb_sernum = self.child_relation[self.partnum_74].get("serial_number")
        self.mac_block_size = self.ETH_MAC_BLOCK_SIZE

        # check if this MAC is record into database first
        try:
            log.debug("check if MAC address already exist in database")
            cesiumlib.verify_mac(
                mb_sernum,
                self.partnum_74,
                "0x{}".format(self.mac_address),
                self.mac_block_size,
            )
            log.debug("MAC address verify PASS!")
        except Exception as e:
            log.info(e)
            log.debug("MAC address is not in database, record it!")
            log.debug(
                "MAC_record:{},{},{},{}".format(
                    mb_sernum,
                    self.partnum_74,
                    "0x{}".format(self.mac_address),
                    self.mac_block_size,
                )
            )

            # Kevin: need to check if this is right way to do it compare with autotest
            cesiumlib.record_mac(
                mb_sernum,
                self.partnum_74,
                "0x{}".format(self.mac_address),
                self.mac_block_size,
            )

        return lib.PASS

    @decorator.log_handler2
    def verify_mb_mac(self):
        """
        call cesium lib to verify MAC address that is recorded .
        :return:
        """

        mb_sernum = self.child_relation[self.partnum_74].get("serial_number")
        cesiumlib.verify_mac(
            mb_sernum,
            self.partnum_74,
            "0x{}".format(self.mac_address),
            self.mac_block_size,
        )
        return lib.PASS

    @decorator.log_handler2
    def verify_pca_sn_pn_rev(self):
        """
        Compare cookie_dict['PCB Serial Number'] and cookie_dict['PCA Assembly Number'] against the child_relation
        dictionary that built at ASSY test step of pull_child_relation and test steop of mfg_read_cookie_all should
        aready run to set self.child_relation and self.cookie_dict before it run this check this test step
        :return:
        """
        child_sernum = ""
        child_uuttype = ""
        for key, value in list(self.child_relation.items()):
            if not value.get("serial_number", None):
                log.debug("Could not found serial_number for [{}]".format(key))
                continue
            child_sernum = value["serial_number"]
            child_uuttype = key.replace("@", "").replace("#", "")

        log.debug("child_sernum=[{}], child_uuttype=[{}]".format(child_sernum, child_uuttype))

        if child_sernum != self.cookie_dict["PCB Serial Number"]:
            log.debug("child_sernum=[{}], cookie_dict=[{}]".format(child_sernum, self.cookie_dict["PCB Serial Number"]))
            self.go_to_failure("PCB serial number in cookie mismatch child_relation!")

        if child_uuttype not in self.cookie_dict["PCA Assembly Number"]:
            log.debug(
                "child_uutype=[{}], cookie_dict=[{}]".format(child_uuttype, self.cookie_dict["PCA Assembly Number"])
            )
            self.go_to_failure("PCA Assembly Number in cookie mismatch child_relation!")

        if self.eco_current[self.uuttype]["pca_pn"] not in self.cookie_dict["PCA Assembly Number"]:
            self.go_to_failure("PCA Assembly Number in cookie mismatch ECO definition!")

        self.partnum_74 = child_uuttype
        self.partnum_74_revision = self.cookie_dict["PCA Revision Number"]

        return lib.PASS

    @decorator.log_handler2
    def mfg_prog_cookie(self):
        """
        Program the cookies related to product information
        :return:
        """
        # self.vid are set in pre-sequence on QR code scan
        # self.tan, self.tan_rev and self.basepid are set in verify_pid_vid
        domain = self.basepid[-3:] if "ROW" in self.basepid else self.basepid[-1]
        cookie_dict_prog = {
            self.COOKIE_PROG_DICT["Top Assembly Serial Number"][0]: self.sernum,
            self.COOKIE_PROG_DICT["Product/Model Number"][0]: self.basepid,
            self.COOKIE_PROG_DICT["PEP Product Identifier (PID)"][0]: self.basepid,
            self.COOKIE_PROG_DICT["PEP Version Identifier (VID)"][0]: self.vid,
            self.COOKIE_PROG_DICT["Top Assembly Part Number"][0]: self.convert_pn_hex(self.tan),
            self.COOKIE_PROG_DICT["Top Revision Number"][0]: self.tan_revision,
            self.COOKIE_PROG_DICT["Radio(2.4G) Carrier Set"][0]: self.DOMAIN_CARRIER_SETTING[domain][0],
            self.COOKIE_PROG_DICT["Radio(5G) Carrier Set"][0]: self.DOMAIN_CARRIER_SETTING[domain][1],
            self.COOKIE_PROG_DICT["Radio(6G) Carrier Set"][0]: self.DOMAIN_CARRIER_SETTING[domain][1],
            self.COOKIE_PROG_DICT["Radio(58) Carrier Set"][0]: self.DOMAIN_CARRIER_SETTING[domain][1],
            self.COOKIE_PROG_DICT["Mfr Service Date"][0]: (datetime.utcnow() + timedelta(days=0)).strftime("%Y%m%d"),
            self.COOKIE_PROG_DICT["Static AP Mode"][0]: self.COOKIE_PROG_DICT["Static AP Mode"][1],
            self.COOKIE_PROG_DICT["Device Type"][0]: self.COOKIE_PROG_DICT["Device Type"][1],
            self.COOKIE_PROG_DICT["Max Association Allowed"][0]: self.COOKIE_PROG_DICT["Max Association Allowed"][1],
            self.COOKIE_PROG_DICT["Radio(802.11g) Radio Mode"][0]: self.COOKIE_PROG_DICT["Radio(802.11g) Radio Mode"][
                1
            ],
            self.COOKIE_PROG_DICT["Radio(2.4G) Antenna Diversity Support"][0]: self.COOKIE_PROG_DICT[
                "Radio(2.4G) Antenna Diversity Support"
            ][1],
            self.COOKIE_PROG_DICT["Radio(2.4G) Encryption Ability"][0]: self.COOKIE_PROG_DICT[
                "Radio(2.4G) Encryption Ability"
            ][1],
            self.COOKIE_PROG_DICT["Radio(2.4G) Max Transmit Power Level"][0]: self.COOKIE_PROG_DICT[
                "Radio(2.4G) Max Transmit Power Level"
            ][1],
            self.COOKIE_PROG_DICT["Radio(5G) Antenna Diversity Support"][0]: self.COOKIE_PROG_DICT[
                "Radio(5G) Antenna Diversity Support"
            ][1],
            self.COOKIE_PROG_DICT["Radio(5G) Encryption Ability"][0]: self.COOKIE_PROG_DICT[
                "Radio(5G) Encryption Ability"
            ][1],
            self.COOKIE_PROG_DICT["Radio(5G) Max Transmit Power Level"][0]: self.COOKIE_PROG_DICT[
                "Radio(5G) Max Transmit Power Level"
            ][1],
            self.COOKIE_PROG_DICT["Radio(58) Antenna Diversity Support"][0]: self.COOKIE_PROG_DICT[
                "Radio(58) Antenna Diversity Support"
            ][1],
            self.COOKIE_PROG_DICT["Radio(58) Encryption Ability"][0]: self.COOKIE_PROG_DICT[
                "Radio(58) Encryption Ability"
            ][1],
            self.COOKIE_PROG_DICT["Radio(58) Max Transmit Power Level"][0]: self.COOKIE_PROG_DICT[
                "Radio(58) Max Transmit Power Level"
            ][1],
            self.COOKIE_PROG_DICT["Radio(6G) Antenna Diversity Support"][0]: self.COOKIE_PROG_DICT[
                "Radio(6G) Antenna Diversity Support"
            ][1],
            self.COOKIE_PROG_DICT["Radio(6G) Encryption Ability"][0]: self.COOKIE_PROG_DICT[
                "Radio(6G) Encryption Ability"
            ][1],
            self.COOKIE_PROG_DICT["Radio(6G) Max Transmit Power Level"][0]: self.COOKIE_PROG_DICT[
                "Radio(6G) Max Transmit Power Level"
            ][1],
        }
        self.mfg_change_cookie_by_item(cookie_dict_prog)
        return lib.PASS

    @decorator.log_handler2
    def verify_cookie(self):
        """
        Check the cookie to make sure product info are programed into cookie,
        test step of mfg_read_cookie_all should run before checking

        :return:
        """
        domain = self.basepid[-3:] if "ROW" in self.basepid else self.basepid[-1]
        cookie_dict_verify = {
            "Top Assembly Serial Number": self.sernum,
            "Product/Model Number": self.basepid,
            "PEP Product Identifier (PID)": self.basepid,
            "PEP Version Identifier (VID)": self.vid,
            "Top Assembly Part Number": "0" + self.tan,
            "Top Revision Number": self.tan_revision,
            "Radio(2.4G) Carrier Set": self.DOMAIN_CARRIER_SETTING[domain][0][-4:],
            "Radio(5G) Carrier Set": self.DOMAIN_CARRIER_SETTING[domain][1][-4:],
            "Radio(6G) Carrier Set": self.DOMAIN_CARRIER_SETTING[domain][1][-4:],
            "Radio(58) Carrier Set": self.DOMAIN_CARRIER_SETTING[domain][1][-4:],
            "Mfr Service Date": (datetime.utcnow() + timedelta(days=0)).strftime("%Y.%m.%d"),
            "Static AP Mode": self.COOKIE_PROG_DICT["Static AP Mode"][2],
            "Static Client Mode": self.COOKIE_PROG_DICT["Static Client Mode"][2],
            "Device Type": self.COOKIE_PROG_DICT["Device Type"][2],
            "ACT2 ID": self.COOKIE_PROG_DICT["ACT2 ID"][2],
            "Max Association Allowed": self.COOKIE_PROG_DICT["Max Association Allowed"][2],
            "Radio(802.11g) Radio Mode": self.COOKIE_PROG_DICT["Radio(802.11g) Radio Mode"][2],
            "Radio(2.4G) Antenna Diversity Support": self.COOKIE_PROG_DICT["Radio(2.4G) Antenna Diversity Support"][2],
            "Radio(2.4G) Encryption Ability": self.COOKIE_PROG_DICT["Radio(2.4G) Encryption Ability"][2],
            "Radio(2.4G) Max Transmit Power Level": self.COOKIE_PROG_DICT["Radio(2.4G) Max Transmit Power Level"][2],
            "Radio(5G) Antenna Diversity Support": self.COOKIE_PROG_DICT["Radio(5G) Antenna Diversity Support"][2],
            "Radio(5G) Encryption Ability": self.COOKIE_PROG_DICT["Radio(5G) Encryption Ability"][2],
            "Radio(5G) Max Transmit Power Level": self.COOKIE_PROG_DICT["Radio(5G) Max Transmit Power Level"][2],
            "Radio(58) Antenna Diversity Support": self.COOKIE_PROG_DICT["Radio(58) Antenna Diversity Support"][2],
            "Radio(58) Encryption Ability": self.COOKIE_PROG_DICT["Radio(58) Encryption Ability"][2],
            "Radio(58) Max Transmit Power Level": self.COOKIE_PROG_DICT["Radio(58) Max Transmit Power Level"][2],
            "Radio(49) Antenna Diversity Support": self.COOKIE_PROG_DICT["Radio(49) Antenna Diversity Support"][2],
            "Radio(49) Encryption Ability": self.COOKIE_PROG_DICT["Radio(49) Encryption Ability"][2],
            "Radio(49) Max Transmit Power Level": self.COOKIE_PROG_DICT["Radio(49) Max Transmit Power Level"][2],
            "Radio(6G) Antenna Diversity Support": self.COOKIE_PROG_DICT["Radio(6G) Antenna Diversity Support"][2],
            "Radio(6G) Encryption Ability": self.COOKIE_PROG_DICT["Radio(6G) Encryption Ability"][2],
            "BLE/IOT Chip type": self.COOKIE_PROG_DICT["BLE/IOT Chip type"][2],
            "Power Monitor type": self.COOKIE_PROG_DICT["Power Monitor type"][2],
            "Board ID": self.COOKIE_PROG_DICT["Board ID"][2],
            "Aurora Factory Boot Select": self.COOKIE_PROG_DICT["Aurora Factory Boot Select"][2],
            "Product/PID Number": self.basepid,
        }

        for key, value in list(cookie_dict_verify.items()):
            log.debug("Checking '{}': [{}] against cookie [{}]".format(key.ljust(30), value, self.cookie_dict[key]))
            if key == "Mfr Service Date":
                if value != self.cookie_dict[key][:10]:
                    self.go_to_failure("{} - [{}] mismatch cookie[{}]".format(key, value, self.cookie_dict[key][:10]))
            elif key == "Power Monitor type":
                if self.cookie_dict[key] not in value:
                    self.go_to_failure(
                        "{} - [{}] not in cookie_value_list({})".format(key, value, self.cookie_dict[key])
                    )
            elif value != self.cookie_dict[key]:
                self.go_to_failure("{} - [{}] mismatch cookie[{}]".format(key, value, self.cookie_dict[key]))
        return lib.PASS

    @decorator.log_handler2
    def verify_radio_carrier_cmpd(self):
        """Verify the radio_carrier setting in cookie data against CMPD.

        :return:
        """
        cmpd_type_list = [
            "A domain",
            "B domain",
            "E domain",
            "F domain",
            "Q domain",
            "R domain",
            "Z domain",
            "ROW domain",
        ]

        cmpd_value_list = [
            "0000,000B,000B",
            "0000,0029,0029",
            "0001,000C,000C",
            "0031,0032,0032",
            "002D,002E,002E",
            "0001,002A,002A",
            "0000,0030,0030",
            "003A,003B,003B",
        ]

        domain = self.basepid[-3:] if "ROW" in self.basepid else self.basepid[-1]
        index = cmpd_type_list.index("{} domain".format(domain))
        value = "{},{},{}".format(
            self.cookie_dict["Radio(2.4G) Carrier Set"],
            self.cookie_dict["Radio(5G) Carrier Set"],
            self.cookie_dict["Radio(6G) Carrier Set"],
        )
        cmpd_value_list[index] = value

        log.debug("Update cmpd_value_list[{}] - {} : {}".format(index, cmpd_type_list[index], value))
        try:
            utilities.verify_cmpd(
                cmpd_description="COOKIE",
                uut_type="CW9162",
                part_number="73-12345-01",  # Don't change this value, keep it same as CMPD table
                part_revision="A0",  # Don't change this value, keep it ame as CMPD table
                test_site="ALL",
                cmpd_type_list=cmpd_type_list,
                cmpd_value_list=cmpd_value_list,
                password_family="wnbu_cmpd",
            )
        except Exception as e:
            log.error(e)
            self.go_to_failure("Verify radio carrier CMPD Failed")

        return lib.PASS

    @decorator.log_handler2
    def print_df_pod_label(self):
        """
        Print POD labels per Cisco specification, verify_mb_mac and verify_pid_vid should PASS in order to get correct
        information
        :return:
        """

        label_format = (
            "<label_name>,<printer_name>,<date>,<serial_number>,<clei>,<coo>,<eci>,<tan>,<mac_address>,"
            "<mac_block_size>,<mac_address_offset>,<header1>,<data1>,<header2>,<data2>,<header3>,<data3>,"
            "<header4>,<data4>,<header5>,<data5>,<header6>,<data6>,<header7>,<data7>,<header8>,<data8>,"
            "<header9>,<data9>,<header10>,<data10>,<header11>,<data11>,<header12>,<data12>"
        )

        # check the flag in site_config, False - skip label print, True - print label
        # default return is True (print label) if it doesn't exist in site_config
        if self.site_config.get("print_assy_label", "true").lower() in ["false"]:
            return lib.SKIPPED

        log.info("95-spec to refer 95-115301-xx")
        if "TSP" in self.site_config.get("top_sernum_prefix"):
            pod_compliance = self.POD_COMPLIANCE.get(self.uuttype + "_TSP")
        else:
            pod_compliance = self.POD_COMPLIANCE.get(self.uuttype)
        label_tags = dict(
            label_name=pod_compliance.get("label_name"),
            printer_name=self.site_config.get("pod_printer_name"),
            date=time.strftime("%m/%Y").upper(),
            serial_number=self.sernum,
            clei=self.meraki_sernum,  # Set CLEI to meraki_sernum for CM6x PIDs.
            coo=self.site_config.get("coo"),
            eci="",
            tan=self.tan + " " + self.tan_revision,  # self.tan and rev come from ECO definition
            mac_address=self.mac_address,  # self.mac_address come from QR label in scan
            mac_block_size="CiscoAirProvision",
            mac_address_offset="WPA2-PSK",
            header1="PID VID: ",
            data1=self.uuttype + " " + self.vid,  # self.vid come from ECO definition
            header2=pod_compliance.get("header2"),
            data2=self.container[-2:],
            header3=pod_compliance.get("header3"),
            data3=pod_compliance.get("data3"),
            header4="",
            data4="",
            header5=pod_compliance.get("header5"),
            data5=self.uuttype,
            header6=pod_compliance.get("header6"),
            data6="",
            header7="",
            data7="Password",
            header8=pod_compliance.get("header8"),
            data8=pod_compliance.get("data8"),
            header9=pod_compliance.get("header9"),
            data9="1",
            header10=pod_compliance.get("header10"),
            data10=pod_compliance.get("data10"),
            header11="",
            data11=pod_compliance.get("data11"),
            header12=pod_compliance.get("header12"),
            data12=pod_compliance.get("data12"),
        )

        self.print_label(
            label_format=label_format,
            areas=self.area,
            generate_file=True,
            sftp_host=self.site_config.get("sftp_host_ip"),
            remote_path="LoadDir",
            username=self.site_config.get("username"),  # wnbupod
            password=self.site_config.get("password"),  # wnbupod
            **label_tags
        )
        return lib.PASS

    @decorator.log_handler2
    def finalization(self):
        """
        Close all Apollo connection objects and create test record, this functional is shared by ASSY and SYSFT
        :return:
        """
        kwargs = dict(
            lineid=self.lineid,
            tan=self.tan,
            tan_hw_rev=self.tan_revision,
            swrev=self.sw_image_name[:35] if len(self.sw_image_name) > 35 else self.sw_image_name,
            board_part_num=self.partnum_74,
            board_hw_rev=self.partnum_74_revision,
            version_id=self.vid,
            basepid=self.basepid,
            testr1name="MFG image",
            testr1=self.mfg_image,
            testr2name="MERAKI_SN",
            testr2=self.meraki_sernum,
            testr3name="SW PID + PID",
            testr3=self.sw_image_pid + "+" + self.pid,
            coo=self.site_config.get("coo"),
            rohs="Y6D",
            prntmac="YES" if "SYSFT" in self.area else None,
        )

        if (
            lib.get_apollo_mode() == definition.PROD
            and lib.apdicts.test_info.current_status == "PASS"
            and "SYSFT" in self.area
        ):
            kwargs.update({"backflush_status": "YES"})

        child_kwargs = dict(
            testr2name="MERAKI_SN",
            testr2=self.meraki_sernum,
        )
        log.debug("********* Add TST data for child *********")
        self.add_tst_data_for_children(**child_kwargs)
        log.debug("********* Add TST data for UUT *********")
        self.add_tst_data_for_main_seq(**kwargs)

        if "UUT" in lib.getconnections():
            self.uut.close()
            self.poe_port_power_off()

        if "LOCAL" in lib.getconnections():
            self.local.close()

        if "PRINTER_QR" in lib.getconnections():
            self.printer_qr.close()

        if "PRINTER" in lib.getconnections():
            self.printer.close()

        super(CW9162Df, self).finalization()
        return lib.PASS
