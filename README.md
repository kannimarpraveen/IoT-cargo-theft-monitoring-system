# IoT Cargo Theft Monitoring System

## Description
Developed an intelligent cargo monitoring system using ESP32, GPS, and multiple sensors to track location and detect anomalies in real-time. The system enhances cargo security by identifying unauthorized access and environmental changes.

## Features
- Real-time GPS tracking
- Motion, tilt, and vibration detection (MPU6050)
- Light-based intrusion detection (LDR)
- Door status monitoring (Reed Switch)
- IoT dashboard using Blynk
- Geofencing with alert system
- Sensor fusion-based anomaly detection

## Hardware Used
- ESP32 DevKit V1
- NEO-6M GPS Module
- MPU6050 IMU Sensor
- LDR Sensor
- Magnetic Reed Switch
- Buzzer & Status LEDs

## Working
The system continuously monitors sensor data and transmits it to the cloud using Wi-Fi. Any abnormal condition such as door opening, excessive motion, light intrusion, or geofence breach triggers alerts via Blynk and activates local alarms.

## Applications
- Cargo security systems
- Logistics monitoring
- Smart transportation
- Anti-theft tracking systems

## Author
Praveen K R
