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

Setup

1. Connect the ESP8266 to your computer using a compatible USB cable.
2. Install the Arduino IDE and configure ESP8266 board support.
3. Open the firmware source code in the Arduino IDE.
4. Enter your Wi-Fi SSID and password in the configuration section.
5. Select the correct ESP8266 board and port.
6. Compile and upload the firmware to the ESP8266.
7. Find the ESP8266’s IP address using the serial monitor or your router’s connected-device list.
8. Enter the ESP8266’s IP address in a web browser to access the dashboard.
9. Configure your device to use the ESP8266’s IP address as its DNS server.
10. For network-wide filtering, configure your router’s DHCP DNS settings to distribute the ESP8266’s IP address to connected devices.
11. Test DNS resolution and verify that the configured blocklist is working.

Limitations

* DNS filtering cannot block every advertisement or tracker.
* Advertisements served from the same domains as website content may not be blocked.
* Applications and devices using alternative DNS services, cached DNS results, or direct IP connections may bypass filtering.
* Incorrect DNS settings may prevent websites or applications from connecting.
* Only devices routing DNS requests through the ESP8266 benefit from its filtering.
* The ESP8266 has limited memory and processing capacity compared with dedicated DNS filtering servers.
* DNS requests forwarded by the current firmware use standard, unencrypted DNS.

Privacy and Security

Protect your Wi-Fi credentials and avoid exposing the ESP8266 dashboard directly to the public internet.

Use trusted blocklists and remember that DNS logs can reveal information about browsing activity. Consider the privacy implications of the upstream DNS resolver you choose.

Keep the firmware updated and use a reliable power supply to help ensure stable operation.

License

This project is under the “Apache” license…
