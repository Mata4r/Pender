
<img src="https://i.postimg.cc/wjL2LFkb/image00002.png" width="330">

![Static Badge](https://img.shields.io/badge/esp8266-purple?style=for-the-badge&logo=https%3A%2F%2Fshields.io)
![Static Badge](https://img.shields.io/badge/Arduino-9295EC?style=for-the-badge&label=IDE&labelColor=purple)
![Static Badge](https://img.shields.io/badge/Ad%20Blocker-9295EC?style=for-the-badge)



# Pender — Ad Blocker

A DNS-based ad-blocking project that uses WireGuard to route DNS traffic through the configured network and a blocklist to filter known advertising and tracking domains.

<a>
  <img src="https://i.postimg.cc/dtH3kbNr/IMG-2300.jpg" width="400">
</a>

Features

* ESP8266-based DNS filtering
* DNS-based ad and tracker blocking
* Domain filtering using a configurable blocklist
* DNS request forwarding to an upstream resolver
* Web dashboard for monitoring DNS activity
* Network-level filtering for devices configured to use the ESP8266 as their DNS server

How It Works

The ESP8266 runs a lightweight DNS filtering service. When a device sends a DNS request to the ESP8266, the firmware checks the requested domain against its configured blocklist.

If the domain is blocked, the ESP8266 returns a blocking response. Otherwise, it forwards the DNS request to the configured upstream DNS resolver, which processes the request and returns a response.

Requirements

* ESP8266 development board, such as NodeMCU or Wemos D1 mini
* Compatible Micro-USB cable
* Computer with the Arduino IDE installed
* Wi-Fi network with internet access
* ESP8266 board support and the appropriate USB drivers


## Pender — Setup Instructions

1. Connect the ESP8266 to your computer using a compatible USB cable.
2. Install the Arduino IDE and configure ESP8266 board support.
3. Open the updated firmware source code in the Arduino IDE.
4. Select the correct ESP8266 board and serial port.
5. Compile and upload the firmware to the ESP8266.
6. On your phone or computer, connect to the ESP8266 Wi-Fi network:
   - **Wi-Fi name:** `pender`
   - **Password:** `pender1234`
7. Open a web browser and navigate to `http://192.168.4.1`.
8. Open the Wi-Fi Setup page and enter your home Wi-Fi SSID and password, then save the settings.
9. Allow the ESP8266 to connect to your home network. Your router will automatically assign it an IP address using DHCP.
10. Find the assigned home-network IP address on the dashboard. Connect your device to the same home Wi-Fi network and enter that IP address in your browser to access the dashboard.
11. Configure your device to use the ESP8266's IP address as its DNS server to test DNS filtering.
12. For network-wide filtering, configure your router's DHCP DNS settings to distribute the ESP8266's IP address to connected devices, if supported.

**Note:** The ESP8266 must remain powered on for DNS filtering to work.

Limitations

* DNS filtering cannot block every advertisement or tracker.
* Advertisements served from the same domains as website content may not be blocked.
* Applications and devices using alternative DNS services, cached DNS results, or direct IP connections may bypass filtering.
* Incorrect DNS settings may prevent websites or applications from connecting.
* Only devices routing DNS requests through the ESP8266 benefit from its filtering.
* The ESP8266 has limited memory and processing capacity compared with dedicated DNS filtering servers.
* DNS requests forwarded by the current firmware use standard, unencrypted DNS.

License

This project is under the “Apache” license…
