import time
import json
import network
import ntptime
import hashlib
import binascii
import os
from machine import Pin, ADC
from umqtt.simple import MQTTClient

DEVICE_ID = "escola-nivel-01"
TOPIC_PREFIX = "COLE_AQUI"
HMAC_KEY_HEX = "COLE_AQUI"

WIFI_SSID = "Wokwi-GUEST"
WIFI_PASSWORD = ""
BROKER = "broker.hivemq.com"
USE_TLS = True            # se o TLS falhar no simulador, mude para False (porta 1883)
INTERVAL_S = 5
LOW_LEVEL_ALARM = 20.0    # % abaixo do qual o alarme local acende

TOPIC = TOPIC_PREFIX + "/escola/" + DEVICE_ID
KEY = binascii.unhexlify(HMAC_KEY_HEX) if HMAC_KEY_HEX != "COLE_AQUI" else b""
BOOT_ID = binascii.hexlify(os.urandom(4)).decode()   # muda a cada boot

adc = ADC(Pin(34))
adc.atten(ADC.ATTN_11DB)   # faixa 0-3,3 V
led = Pin(2, Pin.OUT)


# --------------------------------------------------------------- HMAC
# HMAC(K, m) = H( (K' xor opad) || H( (K' xor ipad) || m ) )
# com H = SHA-256, bloco B = 64 bytes, K' = K completado com zeros até B,
# ipad = 0x36 repetido e opad = 0x5c repetido (RFC 2104).
def hmac_sha256(key, msg):
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key + b"\x00" * (block - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = hashlib.sha256(ipad + msg).digest()
    return hashlib.sha256(opad + inner).digest()


def iso_utc():
    t = time.gmtime()
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (t[0], t[1], t[2], t[3], t[4], t[5])


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(WIFI_SSID, WIFI_PASSWORD)
    print("Conectando ao WiFi", end="")
    while not wlan.isconnected():
        print(".", end="")
        time.sleep(0.2)
    print(" ok", wlan.ifconfig()[0])


def sync_clock():
    # o horário entra na mensagem; a ponte rejeita mensagens fora da janela
    while True:
        try:
            ntptime.settime()
            print("Relogio sincronizado (UTC):", iso_utc())
            return
        except Exception as exc:
            print("NTP falhou, tentando de novo:", exc)
            time.sleep(2)


def connect_mqtt():
    client_id = DEVICE_ID + "-" + BOOT_ID
    if USE_TLS:
        try:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.verify_mode = ssl.CERT_NONE   # limitação: sem verificação do broker público
            client = MQTTClient(client_id, BROKER, port=8883, keepalive=60, ssl=ctx)
        except (AttributeError, TypeError, ImportError):
            client = MQTTClient(client_id, BROKER, port=8883, keepalive=60, ssl=True)
    else:
        client = MQTTClient(client_id, BROKER, port=1883, keepalive=60)
    client.connect()
    print("MQTT conectado a", BROKER, "TLS" if USE_TLS else "SEM TLS")
    return client


def read_level():
    return round(adc.read() * 100.0 / 4095.0, 1)


def main():
    if not KEY:
        print("ERRO: preencha HMAC_KEY_HEX e TOPIC_PREFIX (python pki/pki.py hmac-show escola-nivel-01)")
        return
    connect_wifi()
    sync_clock()
    client = connect_mqtt()
    seq = 0
    while True:
        level = read_level()
        alarm = level < LOW_LEVEL_ALARM
        led.value(1 if alarm else 0)          # alarme local: funciona sem rede

        seq += 1
        body = json.dumps({
            "device_id": DEVICE_ID,
            "space": "escola",
            "sensor": "nivel_reservatorio",
            "value": level,
            "unit": "%",
            "alarm_local": alarm,
            "boot_id": BOOT_ID,
            "seq": seq,
            "ts": iso_utc(),
        })
        sig = binascii.hexlify(hmac_sha256(KEY, body.encode())).decode()
        envelope = json.dumps({"body": body, "sig": sig})
        try:
            client.publish(TOPIC, envelope)
            print("seq=%d nivel=%.1f%% alarme=%s" % (seq, level, alarm))
        except OSError as exc:
            print("Falha ao publicar, reconectando:", exc)
            time.sleep(2)
            client = connect_mqtt()
        time.sleep(INTERVAL_S)


main()
