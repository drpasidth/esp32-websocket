from machine import Pin, I2C, UART, reset as mcu_reset, disable_irq, enable_irq
import network
import socket
import urequests
import ujson
import time
import gc

try:
    import micropython
except:
    micropython = None

try:
    import ntptime
except:
    ntptime = None

print("\n" + "=" * 40)
print("ESP32 RS485 Web Dashboard")
print("=" * 40 + "\n")

gc.enable()

# WiFi credentials
DEFAULT_SSID = "TP-Link_5B9A"
DEFAULT_PASSWORD = "97180937"
AP_SSID = "ESP32-RS485-Setup"
AP_PASSWORD = "12345678"

# Remote server settings (defaults) for RS485 data
DEFAULT_REMOTE_HOST = "137.184.86.182"
DEFAULT_RS485_REMOTE_PATH = "/iot2025/e089/insertM.php"

remote_host = DEFAULT_REMOTE_HOST
rs485_remote_path = DEFAULT_RS485_REMOTE_PATH

dev_id = "e089"
mc_id = "m-001"
send_interval = 60  # seconds

# Pulse divider and counter remote path
pulse_divider = 10
counter_remote_path = "/iot2025/e089/insert2C.php"
pulse_divider_counter = 0
counter_enabled = True  # Enable/disable counter
rs485_enabled = True    # Enable/disable RS485

# Dashboard header
dashboard_header = "RS485 Monitor"

# RS485 Modbus defaults
RS485_RX_PIN = 26
RS485_TX_PIN = 27
rs485_addr = 1       # slave address
rs485_start = 0      # start register
rs485_count = 4      # number of registers
rs485_baud = 9600    # baudrate

# Scaling factors and labels for RS485 values (display + remote)
k1 = 0.1
k2 = 0.1
k3 = 1.0
k4 = 1.0
label1 = "Temp"
label2 = "Humi"
label3 = "V3"
label4 = "V4"

# Globals
wlan = None
ap = None
server = None
ip_address = "0.0.0.0"
mac_address = "00:00:00:00:00:00"
last_send_ms = 0
last_send_status = "Never"
rs485_regs = None
send_backoff_until_ms = 0

# LCD globals (I2C 1602)
i2c = None
lcd_addr = None
lcd_page = 0
lcd_last_switch_ms = 0
lcd_last_update_ms = 0

# Pulse input (GPIO25)
PULSE_PIN = 25
PULSE_DEBOUNCE_MS = 30

# Power failure detection pin (pin 34 with 2k-2k divider from 3.3V)
POWER_FAILURE_PIN = 34
pulse_pin = None
pulse_count = 0
pulse_accm = 0
cpm = 0
pulse_window = 0
_pulse_last_ms = 0
_pulse_sched_pending = 0
_pulse_print_pending = 0
_pulse_print_q = 0
_pulse_print_a = 0

# WiFi IP config
wifi_mode = "dhcp"  # "dhcp" or "static"
wifi_static_ip = ""
wifi_gateway = ""
wifi_subnet = ""

uart_rs485 = None
last_rs485_error = ""
last_rs485_raw_hex = ""
last_rs485_ok_ms = 0

# WebSocket globals
websocket_clients = set()
websocket_last_broadcast_ms = 0
websocket_broadcast_interval_ms = 1000  # Broadcast every 1 second


LCD_COLS = 16
LCD_ROWS = 2


def lcd_write(data):
    if i2c and lcd_addr:
        try:
            i2c.writeto(lcd_addr, bytearray([data | 0x08]))
        except:
            pass


def lcd_pulse(data):
    lcd_write(data | 0x04)
    time.sleep_us(1)
    lcd_write(data)
    time.sleep_us(50)


def lcd_write_nibble(data):
    lcd_write(data)
    lcd_pulse(data)


def lcd_cmd(cmd):
    lcd_write_nibble(cmd & 0xF0)
    lcd_write_nibble((cmd << 4) & 0xF0)


def lcd_char(data):
    lcd_write_nibble(0x01 | (data & 0xF0))
    lcd_write_nibble(0x01 | ((data << 4) & 0xF0))


def lcd_init():
    global i2c, lcd_addr
    try:
        i2c = I2C(0, scl=Pin(22), sda=Pin(21), freq=100000)
        time.sleep_ms(50)
        devices = i2c.scan()
        if not devices:
            return False

        # Most common I2C backpacks
        for addr in (0x27, 0x3F):
            if addr in devices:
                lcd_addr = addr
                break
        if not lcd_addr:
            return False

        time.sleep_ms(50)
        lcd_write_nibble(0x30)
        time.sleep_ms(5)
        lcd_write_nibble(0x30)
        time.sleep_ms(1)
        lcd_write_nibble(0x30)
        time.sleep_ms(1)
        lcd_write_nibble(0x20)
        lcd_cmd(0x28)
        lcd_cmd(0x0C)
        lcd_cmd(0x01)
        time.sleep_ms(2)
        lcd_cmd(0x06)
        return True
    except:
        return False


def lcd_clear():
    if i2c and lcd_addr:
        lcd_cmd(0x01)
        time.sleep_ms(2)


def lcd_set_pos(row, col):
    if i2c and lcd_addr:
        # 16x2 offsets
        offsets = [0x00, 0x40]
        if 0 <= row < LCD_ROWS and 0 <= col < LCD_COLS:
            lcd_cmd(0x80 | (offsets[row] + col))


def lcd_text(text, row=0, col=0):
    if i2c and lcd_addr:
        lcd_set_pos(row, col)
        t = (text or "")
        if len(t) < (LCD_COLS - col):
            t = t + (" " * ((LCD_COLS - col) - len(t)))
        for c in t[: (LCD_COLS - col)]:
            try:
                lcd_char(ord(c))
            except:
                lcd_char(32)


def _format_time_hms():
    try:
        now_utc = time.time()
        now_local = now_utc + 7 * 3600
        t = time.localtime(now_local)
        return "{:02d}:{:02d}:{:02d}".format(t[3], t[4], t[5])
    except:
        return "--:--:--"


def update_lcd_1602():
    global lcd_page, lcd_last_switch_ms

    if not i2c or not lcd_addr:
        return

    now = time.ticks_ms()
    if time.ticks_diff(now, lcd_last_switch_ms) >= 5000:
        lcd_page = (lcd_page + 1) % 3
        lcd_last_switch_ms = now

    if lcd_page == 0:
        # Page 0: time + IP
        line1 = _format_time_hms()
        line2 = "IP:" + (ip_address or "")
        lcd_clear()
        lcd_text(line1[:LCD_COLS], 0, 0)
        lcd_text(line2[:LCD_COLS], 1, 0)
        return

    if lcd_page == 1:
        # Page 1: V1..V4
        v1 = v2 = v3 = v4 = None
        if rs485_regs and len(rs485_regs) >= 4:
            v1, v2, v3, v4 = scaled_values_from_regs(rs485_regs)

        def fmt_pair(a_label, a_val, b_label, b_val):
            a = ("%s:%4.1f" % (a_label, a_val)) if a_val is not None else ("%s:---" % a_label)
            b = ("%s:%4.1f" % (b_label, b_val)) if b_val is not None else ("%s:---" % b_label)
            s = (a + " " + b)
            return s[:LCD_COLS]

        line1 = fmt_pair(label1, v1, label2, v2)
        line2 = fmt_pair(label3, v3, label4, v4)
        lcd_clear()
        lcd_text(line1, 0, 0)
        lcd_text(line2, 1, 0)
        return

    # Page 2: Pulse metrics
    try:
        irq_state = disable_irq()
        q = pulse_count
        a = pulse_accm
        p = cpm
        enable_irq(irq_state)
    except:
        q = pulse_count
        a = pulse_accm
        p = cpm

    line1 = ("Q:%d cpm:%d" % (q, p))[:LCD_COLS]
    line2 = ("Accm:%d" % (a,))[:LCD_COLS]
    lcd_clear()
    lcd_text(line1, 0, 0)
    lcd_text(line2, 1, 0)
    return


def _pulse_scheduled(_):
    global pulse_count, pulse_accm, pulse_window, _pulse_sched_pending
    global _pulse_print_pending, _pulse_print_q, _pulse_print_a
    global pulse_divider_counter
    try:
        pulse_count += 1
        pulse_accm += 1
        pulse_window += 1
        pulse_divider_counter += 1
        _pulse_print_q = pulse_count
        _pulse_print_a = pulse_accm
        _pulse_print_pending = 1
    except:
        pass
    _pulse_sched_pending = 0


def _pulse_irq(_pin):
    global _pulse_last_ms, _pulse_sched_pending
    now = time.ticks_ms()
    if time.ticks_diff(now, _pulse_last_ms) < PULSE_DEBOUNCE_MS:
        return
    _pulse_last_ms = now

    if micropython is not None:
        if _pulse_sched_pending:
            return
        _pulse_sched_pending = 1
        try:
            micropython.schedule(_pulse_scheduled, 0)
        except:
            _pulse_sched_pending = 0
        return

    # Fallback if micropython.schedule is not available
    try:
        pulse_count += 1
        pulse_accm += 1
    except:
        pass


def pulse_init():
    global pulse_pin
    try:
        if micropython is not None:
            try:
                micropython.alloc_emergency_exception_buf(100)
            except:
                pass
        pulse_pin = Pin(PULSE_PIN, Pin.IN, Pin.PULL_UP)
        pulse_pin.irq(trigger=Pin.IRQ_FALLING, handler=_pulse_irq)
        return True
    except:
        pulse_pin = None
        return False


def _power_failure_irq(_pin):
    """Power failure detection - save counters immediately"""
    print("Power failure detected - saving counters")
    try:
        save_device_config()
        print("Counters saved due to power failure")
    except Exception as e:
        print("Error saving on power failure:", str(e))


def power_failure_init():
    """Initialize power failure detection on pin 34"""
    try:
        power_pin = Pin(POWER_FAILURE_PIN, Pin.IN, Pin.PULL_UP)
        power_pin.irq(trigger=Pin.IRQ_FALLING, handler=_power_failure_irq)
        print("Power failure detection enabled on pin", POWER_FAILURE_PIN)
        return True
    except Exception as e:
        print("Power failure init error:", str(e))
        return False


def _bytes_to_hex(data):
    try:
        return " ".join("%02X" % b for b in data)
    except:
        return ""


def _websocket_handshake(request):
    """Extract WebSocket key and generate accept response"""
    try:
        lines = request.split("\r\n")
        key = None
        for line in lines:
            if line.startswith("Sec-WebSocket-Key:"):
                key = line.split(":")[1].strip()
                break
        
        if not key:
            return None
            
        # Generate accept key
        import ubinascii
        import uhashlib
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_key = ubinascii.b2a_base64(uhashlib.sha1((key + magic).encode()).digest()).decode().strip()
        
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n"
        )
        return response
    except:
        return None


def _websocket_send_frame(client, data):
    """Send WebSocket frame with data"""
    try:
        if isinstance(data, str):
            data = data.encode()
        
        # Simple text frame (opcode 0x81)
        frame = bytearray([0x81])  # FIN=1, opcode=1 (text)
        payload_len = len(data)
        
        if payload_len < 126:
            frame.append(payload_len)
        elif payload_len < 65536:
            frame.append(126)
            frame.extend(payload_len.to_bytes(2, 'big'))
        else:
            frame.append(127)
            frame.extend(payload_len.to_bytes(8, 'big'))
            
        frame.extend(data)
        
        try:
            client.send(frame)
        except:
            pass
        return True
    except:
        return False


def _websocket_broadcast(data):
    """Broadcast data to all connected WebSocket clients"""
    global websocket_clients
    if not websocket_clients:
        return
    
    # Remove disconnected clients
    disconnected = []
    for client in websocket_clients:
        try:
            if not _websocket_send_frame(client, data):
                disconnected.append(client)
        except:
            disconnected.append(client)
    
    # Remove disconnected clients
    for client in disconnected:
        try:
            client.close()
        except:
            pass
        websocket_clients.discard(client)


def _format_mac(mac_bytes):
    try:
        return ":".join("%02X" % b for b in mac_bytes)
    except:
        return "00:00:00:00:00:00"


def _url_decode(s):
    try:
        s = s.replace("+", " ")
        out = ""
        i = 0
        length = len(s)
        while i < length:
            ch = s[i]
            if ch == "%" and i + 2 < length:
                hex_part = s[i + 1 : i + 3]
                try:
                    out += chr(int(hex_part, 16))
                    i += 3
                    continue
                except:
                    pass
            out += ch
            i += 1
        return out
    except:
        return s


def save_device_config():
    global pulse_count, pulse_accm, cpm, pulse_divider, counter_enabled, rs485_enabled
    try:
        data = "\n".join([
            dev_id,
            mc_id,
            str(send_interval),
            remote_host,
            rs485_remote_path,
            str(rs485_addr),
            str(rs485_start),
            str(rs485_count),
            str(rs485_baud),
            str(k1),
            str(k2),
            str(k3),
            str(k4),
            label1,
            label2,
            label3,
            label4,
            str(pulse_divider),
            counter_remote_path,
            dashboard_header,
            str(pulse_count),
            str(pulse_accm),
            str(cpm),
            str(counter_enabled),
            str(rs485_enabled),
        ])
        with open("rs485_device_config.txt", "w") as f:
            f.write(data)
        return True
    except Exception as e:
        print("save_device_config error:", str(e))
        return False


def load_device_config():
    global dev_id, mc_id, send_interval, remote_host, rs485_remote_path
    global rs485_addr, rs485_start, rs485_count, rs485_baud
    global k1, k2, k3, k4
    global label1, label2, label3, label4
    global pulse_divider, counter_remote_path, dashboard_header
    global pulse_count, pulse_accm, cpm, counter_enabled, rs485_enabled

    try:
        with open("rs485_device_config.txt", "r") as f:
            lines = f.read().splitlines()
        n = len(lines)

        dev_id = (lines[0].strip() if n > 0 else dev_id) or dev_id
        mc_id = (lines[1].strip() if n > 1 else mc_id) or mc_id
        try:
            send_interval = int((lines[2].strip() if n > 2 else str(send_interval)) or str(send_interval))
        except:
            send_interval = 60
        remote_host = (lines[3].strip() if n > 3 else remote_host) or remote_host
        rs485_remote_path = (lines[4].strip() if n > 4 else rs485_remote_path) or rs485_remote_path
        try:
            rs485_addr = int((lines[5].strip() if n > 5 else str(rs485_addr)) or str(rs485_addr))
        except:
            rs485_addr = 1
        try:
            rs485_start = int((lines[6].strip() if n > 6 else str(rs485_start)) or str(rs485_start))
        except:
            rs485_start = 0
        try:
            rs485_count = int((lines[7].strip() if n > 7 else str(rs485_count)) or str(rs485_count))
        except:
            rs485_count = 4
        try:
            rs485_baud = int((lines[8].strip() if n > 8 else str(rs485_baud)) or str(rs485_baud))
        except:
            rs485_baud = 9600
        try:
            k1 = float((lines[9].strip() if n > 9 else str(k1)) or str(k1))
        except:
            pass
        try:
            k2 = float((lines[10].strip() if n > 10 else str(k2)) or str(k2))
        except:
            pass
        try:
            k3 = float((lines[11].strip() if n > 11 else str(k3)) or str(k3))
        except:
            pass
        try:
            k4 = float((lines[12].strip() if n > 12 else str(k4)) or str(k4))
        except:
            pass

        label1 = (lines[13].strip() if n > 13 else label1) or label1
        label2 = (lines[14].strip() if n > 14 else label2) or label2
        label3 = (lines[15].strip() if n > 15 else label3) or label3
        label4 = (lines[16].strip() if n > 16 else label4) or label4
        # Optional pulse_divider and counter_remote_path
        try:
            pulse_divider = int((lines[17].strip() if n > 17 else str(pulse_divider)) or str(pulse_divider))
        except:
            pulse_divider = 10
        counter_remote_path = (lines[18].strip() if n > 18 else counter_remote_path) or counter_remote_path
        dashboard_header = (lines[19].strip() if n > 19 else dashboard_header) or dashboard_header
        # Load pulse counters from lines 20-22 if available
        try:
            pulse_count = int((lines[20].strip() if n > 20 else str(pulse_count)) or str(pulse_count))
        except:
            pulse_count = 0
        try:
            pulse_accm = int((lines[21].strip() if n > 21 else str(pulse_accm)) or str(pulse_accm))
        except:
            pulse_accm = 0
        try:
            cpm = int((lines[22].strip() if n > 22 else str(cpm)) or str(cpm))
        except:
            cpm = 0
        # Load enable/disable flags from lines 23-24 if available
        try:
            counter_enabled = (lines[23].strip().lower() == "true") if n > 23 else counter_enabled
        except:
            counter_enabled = True
        try:
            rs485_enabled = (lines[24].strip().lower() == "true") if n > 24 else rs485_enabled
        except:
            rs485_enabled = True
        return True
    except Exception as e:
        return False

def save_wifi_config(ssid, password, mode, ip, gateway, subnet):
    try:
        with open("wifi_config.txt", "w") as f:
            f.write((ssid or "") + "\n")
            f.write((password or "") + "\n")
            f.write((mode or "dhcp") + "\n")
            f.write((ip or "") + "\n")
            f.write((gateway or "") + "\n")
            f.write((subnet or "") + "\n")
        return True
    except:
        return False


def load_wifi_config():
    global wifi_mode, wifi_static_ip, wifi_gateway, wifi_subnet

    ssid = DEFAULT_SSID
    password = DEFAULT_PASSWORD
    mode = "dhcp"
    ip = ""
    gateway = ""
    subnet = ""

    try:
        with open("wifi_config.txt", "r") as f:
            lines = f.read().splitlines()

        if len(lines) > 0 and lines[0].strip():
            ssid = lines[0].strip()
        if len(lines) > 1:
            password = lines[1].strip()

        if len(lines) > 2 and lines[2].strip():
            mode = lines[2].strip().lower()
        if len(lines) > 3:
            ip = lines[3].strip()
        if len(lines) > 4:
            gateway = lines[4].strip()
        if len(lines) > 5:
            subnet = lines[5].strip()
    except:
        pass

    if mode not in ("dhcp", "static"):
        mode = "dhcp"

    wifi_mode = mode
    wifi_static_ip = ip
    wifi_gateway = gateway
    wifi_subnet = subnet

    return ssid, password, mode, ip, gateway, subnet


def sync_time_from_internet():
    if not ntptime:
        return False
    try:
        ntptime.settime()
        print("Time synchronized from NTP")
        return True
    except Exception as e:
        print("NTP sync failed:", str(e))
        return False


def _wifi_sta_reset():
    global wlan
    try:
        if wlan is None:
            wlan = network.WLAN(network.STA_IF)
        try:
            wlan.disconnect()
        except:
            pass
        try:
            wlan.active(False)
        except:
            pass
        time.sleep_ms(200)
        try:
            wlan.active(True)
        except:
            pass
        time.sleep_ms(200)
        return True
    except:
        return False


def connect_wifi():
    global wlan, ip_address, mac_address

    ssid, password, mode, static_ip, gateway, subnet = load_wifi_config()
    print("Connecting to:", ssid, "mode=", mode)

    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    try:
        mac_address = _format_mac(wlan.config("mac"))
    except:
        pass

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        if mode == "static" and static_ip and gateway and subnet:
            try:
                wlan.ifconfig((static_ip, subnet, gateway, gateway))
                print("Static IP configured:", static_ip)
            except:
                print("Failed to set static IP, using DHCP")

        try:
            try:
                wlan.disconnect()
            except:
                pass
            time.sleep_ms(200)

            print("WiFi connect attempt {}/{}".format(attempt, max_attempts))
            wlan.connect(ssid, password)
        except Exception as e:
            # Common on some ESP32 builds: RuntimeError Wifi Unknown Error 0x0102
            print("wlan.connect error:", repr(e))
            _wifi_sta_reset()
            continue

        for i in range(20):
            if wlan.isconnected():
                ip_address = wlan.ifconfig()[0]
                print("Connected! IP:", ip_address)
                print("Network config:", wlan.ifconfig())
                print("Subnet mask:", wlan.ifconfig()[1])
                print("Gateway:", wlan.ifconfig()[2])
                print("DNS:", wlan.ifconfig()[3])
                sync_time_from_internet()
                return True
            time.sleep(1)

        print("WiFi attempt failed")
        _wifi_sta_reset()

    print("WiFi connection failed - switching to AP mode")
    return False


def start_ap_mode():
    global ap, ip_address, mac_address

    print("Starting AP Mode:", AP_SSID)

    # Disable STA to avoid mixed-mode edge cases on some firmware builds
    try:
        sta = network.WLAN(network.STA_IF)
        try:
            sta.disconnect()
        except:
            pass
        sta.active(False)
    except:
        pass

    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    ap.config(essid=AP_SSID, password=AP_PASSWORD, authmode=3)

    # Force a known private IP range for setup portal
    try:
        ap.ifconfig(("192.168.4.1", "255.255.255.0", "192.168.4.1", "192.168.4.1"))
    except:
        pass

    time.sleep(1)
    ip_address = ap.ifconfig()[0]

    try:
        mac_address = _format_mac(ap.config("mac"))
    except:
        pass

    print("AP IP:", ip_address)
    return True


def get_remote_url(path_override=None):
    path = path_override if path_override is not None else (rs485_remote_path or "/")
    if not path.startswith("/"):
        path = "/" + path
    return "http://{}{}".format(remote_host, path)


def modbus_crc(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def rs485_init():
    global uart_rs485
    try:
        uart_rs485 = UART(
            2,
            baudrate=rs485_baud,
            bits=8,
            parity=None,
            stop=1,
            tx=RS485_TX_PIN,
            rx=RS485_RX_PIN,
            timeout=1000,
        )
        print(
            "RS485 UART initialized (UART2 TX={}, RX={}, baud={})".format(
                RS485_TX_PIN, RS485_RX_PIN, rs485_baud
            )
        )
        return True
    except Exception as e:
        print("RS485 init error:", str(e))
        return False

    try:
        last_rs485_error = ""
        last_rs485_raw_hex = ""

        req = bytearray(
            [
                slave_id,
                0x03,
                (start_reg >> 8) & 0xFF,
                start_reg & 0xFF,
                (count >> 8) & 0xFF,
                count & 0xFF,
            ]
        )
        crc = modbus_crc(req)
        req.append(crc & 0xFF)
        req.append((crc >> 8) & 0xFF)

        # Match known-good pattern: clear, write, wait, read once
        try:
            uart_rs485.read()
        except:
            pass

        uart_rs485.write(req)
        time.sleep_ms(150)

        resp = uart_rs485.read()
        if not resp:
            last_rs485_error = "No response"
            return None

        last_rs485_raw_hex = _bytes_to_hex(resp)

        if len(resp) < 5:
            last_rs485_error = "Short response"
            return None
        if resp[0] != slave_id or resp[1] != 0x03:
            last_rs485_error = "Header mismatch"
            return None

        byte_count = resp[2]
        expected_len = 3 + byte_count + 2
        if len(resp) < expected_len:
            last_rs485_error = "Incomplete frame"
            return None

        data = resp[3 : 3 + byte_count]
        recv_crc = resp[3 + byte_count] | (resp[3 + byte_count + 1] << 8)
        calc_crc = modbus_crc(resp[: 3 + byte_count])
        if recv_crc != calc_crc:
            last_rs485_error = "CRC mismatch"
            return None

        regs = []
        for i in range(0, byte_count, 2):
            regs.append((data[i] << 8) | data[i + 1])

        last_rs485_ok_ms = time.ticks_ms()
        return regs

    except Exception as e:
        last_rs485_error = repr(e)
        return None


def scaled_values_from_regs(regs):
    if not regs or len(regs) < 4:
        return None, None, None, None
    r1, r2, r3, r4 = regs[0], regs[1], regs[2], regs[3]
    return r1 * k1, r2 * k2, r3 * k3, r4 * k4


def api_json():
    if rs485_regs and len(rs485_regs) >= 4:
        r1, r2, r3, r4 = rs485_regs[0], rs485_regs[1], rs485_regs[2], rs485_regs[3]
        v1, v2, v3, v4 = scaled_values_from_regs(rs485_regs)
    else:
        r1 = r2 = r3 = r4 = None
        v1 = v2 = v3 = v4 = None

    age_ms = None
    try:
        if last_rs485_ok_ms:
            age_ms = time.ticks_diff(time.ticks_ms(), last_rs485_ok_ms)
    except:
        age_ms = None

    payload = {
        "r1": r1,
        "r2": r2,
        "r3": r3,
        "r4": r4,
        "v1": v1,
        "v2": v2,
        "v3": v3,
        "v4": v4,
        "rs485_addr": rs485_addr,
        "rs485_start": rs485_start,
        "rs485_count": rs485_count,
        "rs485_baud": rs485_baud,
        "last_rs485_error": last_rs485_error,
        "last_rs485_raw": last_rs485_raw_hex,
        "last_rs485_age_ms": age_ms,
        "label1": label1,
        "label2": label2,
        "label3": label3,
        "label4": label4,
        "devid": dev_id,
        "mcid": mc_id,
        "interval": send_interval,
        "ip": ip_address,
        "mac": mac_address,
        "last_send": last_send_status,
        "pulse_count": pulse_count,
        "pulse_accm": pulse_accm,
        "cpm": cpm,
    }

    return ujson.dumps(payload)


def send_rs485_to_remote():
    global last_send_status, send_backoff_until_ms

    if not rs485_regs or len(rs485_regs) < 4:
        last_send_status = "No RS485 data"
        return False

    try:
        v1, v2, v3, v4 = scaled_values_from_regs(rs485_regs)
        base_url = get_remote_url()
        url = "%s?devid=%s&mcid=%s&v1=%.3f&v2=%.3f&v3=%.3f&v4=%.3f" % (
            base_url,
            dev_id,
            mc_id,
            v1,
            v2,
            v3,
            v4,
        )
        print("RS485 URL:", url)

        resp = urequests.get(url, timeout=2)
        code = resp.status_code
        resp.close()

        if code == 200:
            last_send_status = "OK"
            return True

        last_send_status = "Err:" + str(code)
        return False

    except Exception as e:
        last_send_status = "Err:" + str(e)[:10]
        try:
            send_backoff_until_ms = time.ticks_ms() + 300000
        except:
            pass
        return False


def dashboard_page():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>RS485 Dashboard</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <style>
    body{font-family:Arial;margin:0;padding:20px;background:#0f0f23;color:#fff;}
    h1{text-align:center;color:#00d4ff;}
    .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:15px;max-width:520px;margin:auto;}
    .card{background:linear-gradient(135deg,#1a1a3e,#2d2d5a);padding:20px;border-radius:15px;text-align:center;}
    .value{font-size:32px;font-weight:bold;color:#00ff88;}
    .label{font-size:14px;color:#888;margin-top:5px;}
    .status{text-align:center;color:#666;margin-top:20px;font-size:12px;}
    .online{color:#00ff88;}
    .menu{text-align:center;margin-top:20px;}
    .menu a{color:#e94560;margin:0 10px;}
    .info{text-align:center;background:#1a1a3e;padding:10px;border-radius:10px;margin-top:15px;max-width:520px;margin-left:auto;margin-right:auto;}
  </style>
</head>
<body>
  <h1>%s</h1>
  <div class=\"grid\">
    <div class=\"card\"><div class=\"value\" id=\"v1\">---</div><div class=\"label\" id=\"l1\">---</div></div>
    <div class=\"card\"><div class=\"value\" id=\"v2\">---</div><div class=\"label\" id=\"l2\">---</div></div>
    <div class=\"card\"><div class=\"value\" id=\"v3\">---</div><div class=\"label\" id=\"l3\">---</div></div>
    <div class=\"card\"><div class=\"value\" id=\"v4\">---</div><div class=\"label\" id=\"l4\">---</div></div>
  </div>

  <div class="info">
    <span>Device: <b id="devid">---</b></span> |
    <span>Machine: <b id="mcid">---</b></span> |
    <span>Send: <b id="interval">---</b>s</span>
  </div>

  <div class="info">
    <span>Qty: <b id="qty">---</b></span> |
    <span>Accm: <b id="accm">---</b></span> |
    <span>CPM: <b id="cpm">---</b></span>
  </div>

  <p class="status">IP: <span id="ip">---</span> | <span class="online" id="status">Updating...</span></p>

  <div class=\"menu\">
    <a href=\"/settings\">Settings</a> |
    <a href=\"/send\">Send Now</a> |
    <a href=\"/setup\">WiFi Setup</a>
  </div>

  <script>
    function updateDashboard(data) {
      // Update RS485 values
      if(data.v1 !== null) document.getElementById('v1').textContent = data.v1.toFixed(1);
      if(data.v2 !== null) document.getElementById('v2').textContent = data.v2.toFixed(1);
      if(data.v3 !== null) document.getElementById('v3').textContent = data.v3.toFixed(1);
      if(data.v4 !== null) document.getElementById('v4').textContent = data.v4.toFixed(1);
      
      // Update labels
      document.getElementById('l1').textContent = data.label1 || 'V1';
      document.getElementById('l2').textContent = data.label2 || 'V2';
      document.getElementById('l3').textContent = data.label3 || 'V3';
      document.getElementById('l4').textContent = data.label4 || 'V4';
      document.getElementById('devid').textContent = data.devid || '';
      document.getElementById('mcid').textContent = data.mcid || '';
      document.getElementById('interval').textContent = data.interval || '';
      document.getElementById('qty').textContent = data.pulse_count || '0';
      document.getElementById('accm').textContent = data.pulse_accm || '0';
      document.getElementById('cpm').textContent = data.cpm || '0';
      document.getElementById('ip').textContent = data.ip || '';
      document.getElementById('status').textContent = 'Live (WebSocket)';
    }

    // Try WebSocket first, fallback to SSE
    let useWebSocket = false;
    let ws = null;
    let eventSource = null;

    function initWebSocket() {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(protocol + '//' + window.location.host + '/events');
        
        ws.onopen = function() {
          console.log('WebSocket connected');
          useWebSocket = true;
          document.getElementById('status').textContent = 'Live (WebSocket)';
        };
        
        ws.onmessage = function(event) {
          try {
            const data = JSON.parse(event.data);
            updateDashboard(data);
          } catch(e) {
            console.error('WebSocket data error:', e);
          }
        };
        
        ws.onerror = function(event) {
          console.log('WebSocket error, falling back to SSE');
          useWebSocket = false;
          initSSE();
        };
        
        ws.onclose = function(event) {
          console.log('WebSocket closed, falling back to SSE');
          useWebSocket = false;
          initSSE();
        };
      } catch(e) {
        console.log('WebSocket not supported, using SSE');
        initSSE();
      }
    }

    function initSSE() {
      eventSource = new EventSource('/events');
      eventSource.onmessage = function(event) {
        try {
          const data = JSON.parse(event.data);
          updateDashboard(data);
        } catch(e) {
          console.error('SSE data error:', e);
        }
      };
      
      eventSource.onerror = function(event) {
        document.getElementById('status').textContent = 'Connection error - retrying...';
        setTimeout(() => {
          window.location.reload();
        }, 5000);
      };
      
      document.getElementById('status').textContent = 'Live (SSE)';
    }

    // Start with WebSocket
    initWebSocket();
  </script>
</body>
</html>"""
    return html % dashboard_header


def wifi_manager_page():
    ssid, password, mode, ip, gateway, subnet = load_wifi_config()

    html = """<!DOCTYPE html>
<html>
<head>
  <title>WiFi Config</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <style>
    body{font-family:Arial;margin:20px;background:#1a1a2e;color:#fff;}
    .card{background:#16213e;padding:20px;border-radius:10px;max-width:420px;margin:auto;}
    h1{color:#e94560;text-align:center;}
    label{display:block;margin-top:10px;color:#888;}
    input,select{width:100%%;padding:10px;margin:5px 0;border:none;border-radius:5px;box-sizing:border-box;}
    button{width:100%%;padding:12px;background:#e94560;color:#fff;border:none;border-radius:5px;cursor:pointer;font-size:16px;margin-top:15px;}
    .info{background:#0f3460;padding:10px;border-radius:5px;margin-top:15px;font-size:12px;}
    a{color:#00d4ff;}
  </style>
</head>
<body>
  <div class=\"card\">
    <h1>WiFi Config</h1>
    <form action=\"/savewifi\" method=\"GET\">
      <label>SSID</label>
      <input type=\"text\" name=\"ssid\" value=\"%s\" required>
      <label>Password</label>
      <input type=\"password\" name=\"pass\" value=\"%s\">
      <label>Mode</label>
      <select name=\"mode\">
        <option value=\"dhcp\" %s>DHCP</option>
        <option value=\"static\" %s>Static IP</option>
      </select>
      <label>Device IP (Static)</label>
      <input type=\"text\" name=\"ip\" value=\"%s\" placeholder=\"192.168.1.50\">
      <label>Gateway</label>
      <input type=\"text\" name=\"gw\" value=\"%s\" placeholder=\"192.168.1.1\">
      <label>Subnet Mask</label>
      <input type=\"text\" name=\"sub\" value=\"%s\" placeholder=\"255.255.255.0\">
      <button type=\"submit\">Save & Reboot</button>
    </form>
    <div class=\"info\">
      <p>Current IP: %s</p>
      <p>MAC Address: %s</p>
    </div>
    <p style=\"text-align:center;margin-top:10px;\"><a href=\"/\">Back to Dashboard</a></p>
  </div>
</body>
</html>""" % (
        ssid,
        password,
        ("selected" if mode == "dhcp" else ""),
        ("selected" if mode == "static" else ""),
        ip,
        gateway,
        subnet,
        ip_address,
        mac_address,
    )
    return html


def settings_page():
    html = """<!DOCTYPE html>
<html>
<head>
  <title>RS485 Settings</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body{font-family:Arial;margin:20px;background:#1a1a2e;color:#fff;}
    .card{background:#16213e;padding:20px;border-radius:10px;max-width:600px;margin:auto;}
    h1{color:#00d4ff;text-align:center;}
    label{display:block;margin-top:10px;color:#888;}
    input{width:100%%;padding:10px;margin:4px 0;border:none;border-radius:5px;box-sizing:border-box;}
    button{width:100%%;padding:12px;border:none;border-radius:5px;cursor:pointer;font-size:16px;margin-top:12px;}
    .btn-save{background:#00d4ff;color:#000;}
    .btn-resetpulse{background:#ffb300;color:#000;}
    .btn-reboot{background:#ff1744;color:#fff;}
    .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}
    .info{background:#0f3460;padding:10px;border-radius:5px;margin-top:15px;font-size:12px;}
    a{color:#e94560;}
  </style>
</head>
<body>
  <div class="card">
    <h1>RS485 Settings</h1>
    <form action="/savesettings" method="GET">
      <div class="grid">
        <div><label>Device ID</label><input type="text" name="devid" value="%s" required></div>
        <div><label>Machine ID</label><input type="text" name="mcid" value="%s" required></div>
        <div><label>Send Interval (seconds)</label><input type="number" name="interval" value="%d" min="10" max="3600" required></div>
        <div><label>Remote Host</label><input type="text" name="host" value="%s" required></div>
        <div><label>RS485 Remote Path</label><input type="text" name="rs485path" value="%s" required></div>
        <div><label>RS485 Address</label><input type="number" name="rsaddr" value="%d" min="1" max="247" required></div>
        <div><label>RS485 Start Register</label><input type="number" name="rsstart" value="%d" min="0" max="65535" required></div>
        <div><label>RS485 Register Count</label><input type="number" name="rscount" value="%d" min="1" max="125" required></div>
        <div><label>RS485 Baudrate</label><input type="number" name="rsbaud" value="%d" min="1200" max="115200" step="100"></div>
        <div><label>K1</label><input type="number" name="k1" value="%.3f" step="0.001"></div>
        <div><label>K2</label><input type="number" name="k2" value="%.3f" step="0.001"></div>
        <div><label>K3</label><input type="number" name="k3" value="%.3f" step="0.001"></div>
        <div><label>K4</label><input type="number" name="k4" value="%.3f" step="0.001"></div>
        <div><label>Label V1</label><input type="text" name="label1" value="%s" maxlength="6"></div>
        <div><label>Label V2</label><input type="text" name="label2" value="%s" maxlength="6"></div>
        <div><label>Label V3</label><input type="text" name="label3" value="%s" maxlength="6"></div>
        <div><label>Label V4</label><input type="text" name="label4" value="%s" maxlength="6"></div>
        <div><label>Pulse Divider</label><input type="number" name="pulse_divider" value="%d" min="1" max="10000"></div>
        <div><label>Counter Remote Path</label><input type="text" name="counter_remote_path" value="%s"></div>
        <div><label>Dashboard Header</label><input type="text" name="dashboard_header" value="%s" maxlength="30"></div>
        <div><label>Counter Status</label>
          <select name="counter_enabled">
            <option value="true" %s>Enabled</option>
            <option value="false" %s>Disabled</option>
          </select>
        </div>
        <div><label>RS485 Status</label>
          <select name="rs485_enabled">
            <option value="true" %s>Enabled</option>
            <option value="false" %s>Disabled</option>
          </select>
        </div>
      </div>
      <button type="submit" class="btn-save">Save Settings</button>
    </form>

    <form action="/resetpulse" method="GET" style="margin-top:10px;">
      <button type="submit" class="btn-resetpulse">Reset Qty & Accm</button>
    </form>

    <form action="/resetqty" method="GET" style="margin-top:10px;">
      <button type="submit" class="btn-resetpulse">Reset Qty Only</button>
    </form>

    <form action="/resetaccm" method="GET" style="margin-top:10px;">
      <button type="submit" class="btn-resetpulse">Reset Accm Only</button>
    </form>

    <form action="/reboot" method="GET" style="margin-top:10px;">
      <button type="submit" class="btn-reboot">Reboot Device</button>
    </form>

    <div class="info">
      <p>Remote URL: %s</p>
      <p>Counter URL: %s</p>
      <p>Last Send: %s</p>
    </div>

    <p style="text-align:center;margin-top:15px;"><a href="/">Back to Dashboard</a></p>
  </div>
</body>
</html>""" % (
        dev_id,
        mc_id,
        send_interval,
        remote_host,
        rs485_remote_path,
        rs485_addr,
        rs485_start,
        rs485_count,
        rs485_baud,
        k1,
        k2,
        k3,
        k4,
        label1,
        label2,
        label3,
        label4,
        pulse_divider,
        counter_remote_path,
        dashboard_header,
        "selected" if counter_enabled else "",
        "selected" if not counter_enabled else "",
        "selected" if rs485_enabled else "",
        "selected" if not rs485_enabled else "",
        get_remote_url(),
        get_remote_url(counter_remote_path),
        last_send_status,
    )
    return html


def send_pulse_to_remote():
    global pulse_divider_counter, pulse_divider
    try:
        # Manage pulse log file with 200 record limit
        try:
            # Read existing records
            records = []
            try:
                with open("pulse_log.txt", "r") as f:
                    records = f.read().splitlines()
            except:
                pass
            
            # Add new record
            timestamp = _format_time_hms()
            new_record = "{},{},{}".format(timestamp, pulse_count, pulse_accm)
            
            # Insert at beginning and keep only 200 records
            records.insert(0, new_record)
            if len(records) > 200:
                records = records[:200]
            
            # Write back to file
            with open("pulse_log.txt", "w") as f:
                f.write("\n".join(records))
                
        except Exception as e:
            print("Pulse log error:", str(e))
        
        base_url = get_remote_url(counter_remote_path)
        url = "%s?devid=%s&mcid=%s&qty=%d&accm=%d&cpm=%d" % (
            base_url,
            dev_id,
            mc_id,
            pulse_count,
            pulse_accm,
            cpm,
        )
        print("Pulse URL:", url)
        resp = urequests.get(url, timeout=2)
        code = resp.status_code
        resp.close()
        if code == 200:
            print("Pulse send success")
            return True
        else:
            print("Pulse send failed:", code)
            return False
    except Exception as e:
        print("Pulse send error:", str(e))
        return False


def start_web_server():
    global server
    try:
        if server:
            try:
                server.close()
            except:
                pass

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(1)
        server.bind(("0.0.0.0", 80))
        server.listen(2)
        server.setblocking(False)
        print("Web server started on port 80")
        return True
    except Exception as e:
        print("Web server error:", str(e))
        return False


def _send_response(client, status_line, content_type, body, extra_headers=""):
    try:
        if body is None:
            body = b""
        try:
            if isinstance(body, str):
                body = body.encode()
        except:
            pass

        content_length = 0
        try:
            content_length = len(body)
        except:
            content_length = 0

        headers = (
            "HTTP/1.1 "
            + status_line
            + "\r\nContent-Type: "
            + content_type
            + "\r\nConnection: close\r\n"
            + "Content-Length: "
            + str(content_length)
            + "\r\n"
            + (extra_headers or "")
            + "\r\n\r\n"
        )
        try:
            client.send(headers.encode())
        except:
            client.send(headers)

        if body:
            client.send(body)
    except:
        pass


def handle_web_client():
    global dev_id, mc_id, send_interval, remote_host, rs485_remote_path
    global rs485_addr, rs485_start, rs485_count, rs485_baud
    global k1, k2, k3, k4
    global label1, label2, label3, label4
    global dashboard_header, pulse_divider, counter_enabled, rs485_enabled

    if not server:
        return

    try:
        client, addr = server.accept()
        client.settimeout(2)

        try:
            request = client.recv(1024).decode("utf-8")
        except:
            client.close()
            return

        if not request or len(request) < 10:
            client.close()
            return

        elif "GET /events" in request:
            # WebSocket endpoint
            try:
                # Check if this is a WebSocket upgrade request
                if "Upgrade: websocket" in request:
                    handshake = _websocket_handshake(request)
                    if handshake:
                        client.send(handshake.encode())
                        # Add to WebSocket clients
                        websocket_clients.add(client)
                        print("WebSocket client connected, total:", len(websocket_clients))
                        return
                else:
                    # Fallback to SSE for compatibility
                    _send_response(client, "200 OK", "text/event-stream", 
                        "retry: 5000\n\n", 
                        extra_headers="Cache-Control: no-cache\nConnection: keep-alive")
                    # Send initial data
                    try:
                        irq_state = disable_irq()
                        data = {
                            "v1": scaled_values_from_regs(rs485_regs)[0] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 0 else None,
                            "v2": scaled_values_from_regs(rs485_regs)[1] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 1 else None,
                            "v3": scaled_values_from_regs(rs485_regs)[2] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 2 else None,
                            "v4": scaled_values_from_regs(rs485_regs)[3] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 3 else None,
                            "pulse_count": pulse_count,
                            "pulse_accm": pulse_accm,
                            "cpm": cpm,
                            "ip": ip_address,
                            "last_send": last_send_status,
                            "counter_enabled": counter_enabled,
                            "rs485_enabled": rs485_enabled
                        }
                        enable_irq(irq_state)
                        
                        # Send SSE data
                        sse_data = "data: " + ujson.dumps(data) + "\n\n"
                        try:
                            client.send(sse_data.encode())
                        except:
                            pass
                    except:
                        pass
                    return
            except Exception as e:
                print("WebSocket/SSE error:", str(e))
                return

        elif "GET /api" in request:
            try:
                print("HTTP /api")
            except:
                pass
            try:
                body = api_json()
                _send_response(
                    client,
                    "200 OK",
                    "application/json",
                    body,
                    extra_headers="Access-Control-Allow-Origin: *\r\nCache-Control: no-cache",
                )
            except Exception as e:
                _send_response(
                    client,
                    "500 Internal Server Error",
                    "text/plain",
                    "api error: " + repr(e),
                    extra_headers="Cache-Control: no-cache",
                )

        elif "GET /savesettings?" in request:
            try:
                params = request.split("GET /savesettings?")[1].split(" ")[0]
                for param in params.split("&"):
                    if param.startswith("devid="):
                        dev_id = _url_decode(param[6:])
                    elif param.startswith("mcid="):
                        mc_id = _url_decode(param[5:])
                    elif param.startswith("interval="):
                        try:
                            send_interval = int(param[9:])
                        except:
                            pass
                    elif param.startswith("host="):
                        remote_host = _url_decode(param[5:])
                    elif param.startswith("rs485path="):
                        rs_path_raw = _url_decode(param[10:])
                        if not rs_path_raw.startswith("/"):
                            rs_path_raw = "/" + rs_path_raw
                        rs485_remote_path = rs_path_raw
                    elif param.startswith("rsaddr="):
                        try:
                            rs485_addr = int(param[7:])
                        except:
                            pass
                    elif param.startswith("rsstart="):
                        try:
                            rs485_start = int(param[8:])
                        except:
                            pass
                    elif param.startswith("rscount="):
                        try:
                            rs485_count = int(param[8:])
                        except:
                            pass
                    elif param.startswith("rsbaud="):
                        try:
                            rs485_baud = int(param[7:])
                        except:
                            pass
                    elif param.startswith("k1="):
                        try:
                            k1 = float(param.split("=", 1)[1] or str(k1))
                        except:
                            pass
                    elif param.startswith("k2="):
                        try:
                            k2 = float(param.split("=", 1)[1] or str(k2))
                        except:
                            pass
                    elif param.startswith("k3="):
                        try:
                            k3 = float(param.split("=", 1)[1] or str(k3))
                        except:
                            pass
                    elif param.startswith("k4="):
                        try:
                            k4 = float(param.split("=", 1)[1] or str(k4))
                        except:
                            pass
                    elif param.startswith("label1="):
                        val = _url_decode(param[7:])
                        label1 = (val[:6] or label1)
                    elif param.startswith("label2="):
                        val = _url_decode(param[7:])
                        label2 = (val[:6] or label2)
                    elif param.startswith("label3="):
                        val = _url_decode(param[7:])
                        label3 = (val[:6] or label3)
                    elif param.startswith("label4="):
                        val = _url_decode(param[7:])
                        label4 = (val[:6] or label4)
                    elif param.startswith("pulse_divider="):
                        try:
                            pulse_divider = int(param.split("=", 1)[1] or str(pulse_divider))
                        except:
                            pass
                    elif param.startswith("counter_remote_path="):
                        val = _url_decode(param[20:])
                        if not val.startswith("/"):
                            val = "/" + val
                        counter_remote_path = val
                    elif param.startswith("dashboard_header="):
                        val = _url_decode(param[16:])
                        # Remove leading = if present (from form submission)
                        if val.startswith("="):
                            val = val[1:]
                        dashboard_header = (val[:30] or dashboard_header)
                    elif param.startswith("counter_enabled="):
                        val = _url_decode(param[16:])
                        counter_enabled = (val.lower() == "true")
                    elif param.startswith("rs485_enabled="):
                        val = _url_decode(param[15:])
                        rs485_enabled = (val.lower() == "true")

                save_device_config()
                # Reload config to update dashboard_header variable
                load_device_config()
                _send_response(client, "302 Found", "text/plain", "", extra_headers="Location: /settings")
            except Exception as e:
                print("Save settings error:", str(e))
                _send_response(client, "400 Bad Request", "text/plain", "Bad Request")

        elif "GET /reboot" in request:
            _send_response(client, "200 OK", "text/html", "<html><body><h3>Rebooting...</h3></body></html>")
            client.close()
            time.sleep(1)
            mcu_reset()

        elif "GET /resetpulse" in request:
            try:
                irq_state = disable_irq()
                globals()["pulse_count"] = 0
                globals()["pulse_accm"] = 0
                globals()["pulse_window"] = 0
                globals()["cpm"] = 0
                enable_irq(irq_state)
            except:
                # Best-effort fallback
                try:
                    globals()["pulse_count"] = 0
                    globals()["pulse_accm"] = 0
                    globals()["pulse_window"] = 0
                    globals()["cpm"] = 0
                except:
                    pass
            _send_response(client, "302 Found", "text/plain", "", extra_headers="Location: /settings")

        elif "GET /resetqty" in request:
            try:
                irq_state = disable_irq()
                globals()["pulse_count"] = 0
                enable_irq(irq_state)
            except:
                # Best-effort fallback
                try:
                    globals()["pulse_count"] = 0
                except:
                    pass
            _send_response(client, "302 Found", "text/plain", "", extra_headers="Location: /settings")

        elif "GET /resetaccm" in request:
            try:
                irq_state = disable_irq()
                globals()["pulse_accm"] = 0
                enable_irq(irq_state)
            except:
                # Best-effort fallback
                try:
                    globals()["pulse_accm"] = 0
                except:
                    pass
            _send_response(client, "302 Found", "text/plain", "", extra_headers="Location: /settings")

        elif "GET /savewifi?" in request:
            try:
                params = request.split("GET /savewifi?")[1].split(" ")[0]
                ssid = ""
                password = ""
                mode = "dhcp"
                ip = ""
                gateway = ""
                subnet = ""
                for param in params.split("&"):
                    if param.startswith("ssid="):
                        ssid = _url_decode(param[5:])
                    elif param.startswith("pass="):
                        password = _url_decode(param[5:])
                    elif param.startswith("mode="):
                        mode = (_url_decode(param[5:]).lower() or "dhcp")
                    elif param.startswith("ip="):
                        ip = _url_decode(param[3:])
                    elif param.startswith("gw="):
                        gateway = _url_decode(param[3:])
                    elif param.startswith("sub="):
                        subnet = _url_decode(param[4:])

                if ssid:
                    save_wifi_config(ssid, password, mode, ip, gateway, subnet)
                    _send_response(
                        client,
                        "200 OK",
                        "text/html",
                        "<html><body style=\"background:#1a1a2e;color:#fff;text-align:center;padding:50px;font-family:Arial;\"><h1>Saved!</h1><p>Rebooting...</p></body></html>",
                    )
                    client.close()
                    time.sleep(2)
                    mcu_reset()
                else:
                    _send_response(client, "400 Bad Request", "text/plain", "SSID required")
            except Exception as e:
                print("Save WiFi error:", str(e))
                _send_response(client, "400 Bad Request", "text/plain", "Bad Request")

        elif "GET /settings" in request:
            _send_response(client, "200 OK", "text/html", settings_page())

        elif "GET /setup" in request:
            _send_response(client, "200 OK", "text/html", wifi_manager_page())

        elif "GET /send" in request:
            send_rs485_to_remote()
            _send_response(client, "302 Found", "text/plain", "", extra_headers="Location: /")

        else:
            _send_response(client, "200 OK", "text/html", dashboard_page())

        client.close()

    except OSError:
        pass
    except Exception as e:
        print("Client error:", str(e))
    finally:
        try:
            client.close()
        except:
            pass


def main():
    global rs485_regs, last_send_ms, lcd_last_update_ms
    global pulse_count, pulse_window, cpm
    global _pulse_print_pending, _pulse_print_q, _pulse_print_a
    global pulse_divider_counter, websocket_last_broadcast_ms

    print("\nStarting RS485 Web Dashboard...")
    gc.collect()

    load_device_config()

    lcd_ok = lcd_init()
    if lcd_ok:
        try:
            lcd_clear()
            lcd_text("RS485 START", 0, 0)
        except:
            pass

    pulse_ok = pulse_init()

    # Initialize power failure detection
    power_failure_init()

    rs485_ok = rs485_init()

    try:
        wifi_connected = connect_wifi()
    except Exception as e:
        print("connect_wifi fatal error:", repr(e))
        wifi_connected = False
    if not wifi_connected:
        start_ap_mode()

    web_ok = start_web_server()

    print("\n" + "=" * 40)
    print("System Ready!")
    print("=" * 40)
    print("IP:", ip_address)
    print("Web: http://" + ip_address)
    print("API: http://" + ip_address + "/api")
    print("Settings: http://" + ip_address + "/settings")
    print("WiFi Setup: http://" + ip_address + "/setup")
    print("Device ID:", dev_id)
    print("Machine ID:", mc_id)
    print("Send Interval:", send_interval, "seconds")
    print("RS485 UART:", "OK" if rs485_ok else "Failed")
    print("Web Server:", "OK" if web_ok else "Failed")
    print("=" * 40 + "\n")

    rs485_last_read_ms = 0
    rs485_interval_ms = 5000
    last_send_ms = time.ticks_ms()
    last_gc_ms = 0
    lcd_last_update_ms = 0

    cpm_last_calc_ms = time.ticks_ms()

    while True:
        now = time.ticks_ms()

        handle_web_client()

        # Print pulse counters once per pulse (deferred, not from IRQ)
        if _pulse_print_pending:
            try:
                irq_state = disable_irq()
                q = _pulse_print_q
                a = _pulse_print_a
                p = cpm
                _pulse_print_pending = 0
                enable_irq(irq_state)
            except:
                q = _pulse_print_q
                a = _pulse_print_a
                p = cpm
                _pulse_print_pending = 0

            print("Pulse Qty:", q, "Accm:", a, "cpm:", p)

        # Pulse divider send
        if counter_enabled and pulse_divider > 0 and pulse_divider_counter >= pulse_divider:
            send_pulse_to_remote()
            pulse_divider_counter = 0
            # Save pulse counters to config
            save_device_config()

        if i2c and lcd_addr:
            if time.ticks_diff(now, lcd_last_update_ms) >= 1000:
                update_lcd_1602()
                lcd_last_update_ms = now

        if time.ticks_diff(now, rs485_last_read_ms) >= rs485_interval_ms:
            if rs485_enabled:
                regs = rs485_read_registers(start_reg=rs485_start, count=rs485_count, slave_id=rs485_addr)
                if regs is not None:
                    rs485_regs = regs
                    last_rs485_ok_ms = now
            else:
                # RS485 disabled, clear registers
                rs485_regs = None
            rs485_last_read_ms = now

            if rs485_regs is not None:
                try:
                    v1, v2, v3, v4 = scaled_values_from_regs(regs)
                    print(
                        "RS485 regs:",
                        regs,
                        "scaled:",
                        v1,
                        v2,
                        v3,
                        v4,
                    )
                except:
                    print("RS485 regs:", regs)
            else:
                if last_rs485_error:
                    print("RS485 read fail:", last_rs485_error, "raw:", last_rs485_raw_hex)
                else:
                    print("RS485 read fail")
            rs485_last_read_ms = now

        # CPM calculation every minute
        if time.ticks_diff(now, cpm_last_calc_ms) >= 60000:
            try:
                irq_state = disable_irq()
                q = pulse_window
                pulse_window = 0
                enable_irq(irq_state)
            except:
                q = pulse_window
                pulse_window = 0

            cpm = q
            cpm_last_calc_ms = now

        # WebSocket broadcast every second
        if time.ticks_diff(now, websocket_last_broadcast_ms) >= websocket_broadcast_interval_ms:
            try:
                irq_state = disable_irq()
                data = {
                    "v1": scaled_values_from_regs(rs485_regs)[0] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 0 else None,
                    "v2": scaled_values_from_regs(rs485_regs)[1] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 1 else None,
                    "v3": scaled_values_from_regs(rs485_regs)[2] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 2 else None,
                    "v4": scaled_values_from_regs(rs485_regs)[3] if rs485_regs and len(scaled_values_from_regs(rs485_regs)) > 3 else None,
                    "pulse_count": pulse_count,
                    "pulse_accm": pulse_accm,
                    "cpm": cpm,
                    "ip": ip_address,
                    "last_send": last_send_status,
                    "counter_enabled": counter_enabled,
                    "rs485_enabled": rs485_enabled,
                    "label1": label1,
                    "label2": label2,
                    "label3": label3,
                    "label4": label4,
                    "devid": dev_id,
                    "mcid": mc_id,
                    "interval": send_interval
                }
                enable_irq(irq_state)
                
                # Broadcast to WebSocket clients
                _websocket_broadcast(ujson.dumps(data))
                websocket_last_broadcast_ms = now
            except Exception as e:
                print("WebSocket broadcast error:", str(e))

        if wifi_connected and time.ticks_diff(now, last_send_ms) >= (send_interval * 1000):
            if not send_backoff_until_ms or time.ticks_diff(send_backoff_until_ms, now) <= 0:
                send_rs485_to_remote()
                last_send_ms = now
                gc.collect()

        if time.ticks_diff(now, last_gc_ms) > 60000:
            gc.collect()
            last_gc_ms = now

        time.sleep_ms(20)


if __name__ == "__main__":
    main()
