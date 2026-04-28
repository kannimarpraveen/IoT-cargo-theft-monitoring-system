/*
 * ============================================================
 *  ESP32 IoT Cargo Security Monitoring System
 * ============================================================
 *  Hardware:
 *    - ESP32 DevKit V1
 *    - MPU6050 IMU (I2C: SDA=21, SCL=22)
 *    - NEO-6M GPS (UART2: RX=16, TX=17)
 *    - Magnetic Reed Switch (GPIO 34)
 *    - LDR Sensor (GPIO 35, analog)
 *    - Active Buzzer (GPIO 26)
 *    - Status LEDs: Green=GPIO 25, Red=GPIO 27
 *
 *  Libraries required:
 *    - BlynkESP32 (Blynk IoT)
 *    - TinyGPS++ (GPS parsing)
 *    - Adafruit MPU6050 + Adafruit Unified Sensor
 *    - Wire (built-in)
 *    - WiFi (built-in)
 *
 *  Cloud: Blynk IoT (blynk.cloud)
 * ============================================================
 */

//Core & WiFi 
#include <WiFi.h>
#include <WiFiClient.h>
#include <time.h>

//Blynk 
#define BLYNK_TEMPLATE_ID "TMPL34LSrjcXR"
#define BLYNK_TEMPLATE_NAME "Cargo Security System"
#define BLYNK_AUTH_TOKEN "QusGs-eSWb4hcCEeAzI5MJZGadOreS8Z"
#define BLYNK_PRINT         Serial
#include <BlynkSimpleEsp32.h>

//GPS 
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>

// IMU 
#include <MPU6050_light.h>
#include <Wire.h>

#define GEOFENCE_RADIUS 100.0   // meters

// ============================================================
//  USER CONFIGURATION â€” edit before flashing
// ============================================================
const char* WIFI_SSID     = "pooja 1726";
const char* WIFI_PASSWORD = "pooja2004";

// Default geofence center (updated at runtime via Blynk)
double  GEO_BASE_LAT      = 0.0;
double  GEO_BASE_LON      = 0.0;
float   GEO_RADIUS_M      = 200.0;   // metres

// Detection thresholds
const float TILT_THRESHOLD      = 45.0;   // degrees
const float MOVEMENT_THRESHOLD  = 0.8;    // m/sÂ² above baseline
const int   LIGHT_THRESHOLD     = 1500;    // ADC value (0-4095)
const float ANOMALY_Z_THRESHOLD = 3.0;    // z-score

// Alert cooldown (ms) â€” prevents repeated notifications
const unsigned long ALERT_COOLDOWN_MS = 30000UL;  // 30 s

// ============================================================
//  PIN DEFINITIONS
// ============================================================
#define PIN_REED_SWITCH   34   // INPUT (active LOW / HIGH depending on wiring)
#define PIN_LDR           35   // ADC1 channel 7
#define PIN_BUZZER        26   // Active buzzer
#define PIN_LED_GREEN     25
#define PIN_LED_RED       27
#define GPS_RX_PIN        16
#define GPS_TX_PIN        17

// ============================================================
//  BLYNK VIRTUAL PINS
// ============================================================
#define VPIN_DOOR         V0
#define VPIN_TILT         V1
#define VPIN_MOTION       V2
#define VPIN_LIGHT        V3
#define VPIN_GPS_SPEED    V4
#define VPIN_LATITUDE     V5
#define VPIN_LONGITUDE    V6
#define VPIN_SECURITY     V7
#define VPIN_EVENT_LOG    V8
#define VPIN_RISK_SCORE   V9
#define VPIN_GEO_LAT      V10
#define VPIN_GEO_LON      V11
#define VPIN_GEO_RADIUS   V12

// ============================================================
//  TIMING INTERVALS (ms)
// ============================================================
const unsigned long INTERVAL_SENSORS  = 500UL;
const unsigned long INTERVAL_GPS      = 3000UL;
const unsigned long INTERVAL_BLYNK    = 2000UL;
const unsigned long INTERVAL_BASELINE = 10000UL;  // baseline update
const unsigned long INTERVAL_WIFI_CHK = 15000UL;
const unsigned long GPS_TIMEOUT_MS    = 10000UL;  // signal lost after 10 s

// GEOFENCE SETTINGS 
#define GEOFENCE_RADIUS 100.0   // meters

// ============================================================
//  OBJECTS
// ============================================================
TinyGPSPlus       gps;
HardwareSerial    gpsSerial(2);   // UART2
MPU6050           mpu(Wire);
BlynkTimer        blynkTimer;

// ============================================================
//  SYSTEM STATE
// ============================================================
struct SensorData {
  // Reed switch
  bool  doorOpen        = false;

  // MPU6050
  float accelX          = 0, accelY = 0, accelZ = 0;
  float gyroX           = 0, gyroY  = 0, gyroZ  = 0;
  float tiltAngle       = 0;
  float motionMagnitude = 0;

  // GPS
  double  latitude      = 0.0;
  double  longitude     = 0.0;
  float   speed_kmh     = 0.0;
  bool    gpsValid      = false;
  unsigned long lastGpsMs = 0;

  // LDR
  int   lightLevel      = 0;

  // Derived
  float riskScore       = 0;
  int   securityLevel   = 0; // 0=OK, 1=WARNING, 2=ALERT, 3=CRITICAL
} sData;

struct AlertState {
  unsigned long doorAlertLast      = 0;
  unsigned long tiltAlertLast      = 0;
  unsigned long motionAlertLast    = 0;
  unsigned long geoAlertLast       = 0;
  unsigned long lightAlertLast     = 0;
  unsigned long gpsLostAlertLast   = 0;
  unsigned long anomalyAlertLast   = 0;
  bool          buzzerActive       = false;
  unsigned long buzzerStopMs       = 0;
} alertState;
  double refLatitude = 0;
  double refLongitude = 0;
  bool geofenceSet = false;

struct BaselineStats {
  float  sumMotion      = 0;
  float  sumSqMotion    = 0;
  int    count          = 0;
  float  mean           = 0;
  float  stdDev         = 0;
  bool   baselineReady  = false;
  const int MIN_SAMPLES = 20;
} baseline;

// Millis trackers
unsigned long lastSensorMs   = 0;
unsigned long lastGpsMs      = 0;
unsigned long lastBlynkMs    = 0;
unsigned long lastBaselineMs = 0;
unsigned long lastWifiChkMs  = 0;

// ============================================================
//  FORWARD DECLARATIONS
// ============================================================
void readSensors();
void processMotion();
float calculateTilt(float ax, float ay, float az);
double calculateDistance(double lat1, double lon1, double lat2, double lon2);
void checkGeofence();
void detectAnomalies();
void sensorFusion();
void updateBlynk();
void handleAlerts(const char* reason, int level);
void logEvent(const char* event);
String getTimestamp();
void buzzerBeep(int durationMs);
void setStatusLEDs();
void checkWiFiReconnect();
void checkBlynkReconnect();
void readGPS();

// ============================================================
//  BLYNK CALLBACKS receive geofence config from dashboard
// ============================================================
BLYNK_WRITE(VPIN_GEO_LAT) {
  GEO_BASE_LAT = param.asDouble();
  Serial.printf("[BLYNK] Geofence lat updated: %.6f\n", GEO_BASE_LAT);
}
BLYNK_WRITE(VPIN_GEO_LON) {
  GEO_BASE_LON = param.asDouble();
  Serial.printf("[BLYNK] Geofence lon updated: %.6f\n", GEO_BASE_LON);
}
BLYNK_WRITE(VPIN_GEO_RADIUS) {
  GEO_RADIUS_M = param.asFloat();
  Serial.printf("[BLYNK] Geofence radius updated: %.1f m\n", GEO_RADIUS_M);
}

// ============================================================
//  SETUP
// ============================================================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("\n[BOOT] Cargo Security System Starting...");

  //GPIO 
  pinMode(PIN_REED_SWITCH, INPUT_PULLUP);
  pinMode(PIN_BUZZER,      OUTPUT);
  pinMode(PIN_LED_GREEN,   OUTPUT);
  pinMode(PIN_LED_RED,     OUTPUT);
  digitalWrite(PIN_BUZZER,   LOW);
  digitalWrite(PIN_LED_GREEN, LOW);
  digitalWrite(PIN_LED_RED,   LOW);

  //I2C / MPU6050
  Wire.begin(21,22);

  byte status = mpu.begin();

  Serial.print("[IMU] MPU status: ");
  Serial.println(status);

  if(status != 0){
   Serial.println("[ERROR] MPU not responding");
   while(1);
}

   delay(1000);
   Serial.println("[IMU] Calibrating...");
   mpu.calcOffsets();
   Serial.println("[IMU] Calibration done");

  //GPS UART 
  gpsSerial.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
  Serial.println("[OK] GPS UART2 initialized");

  // WiFi 
  Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  unsigned long wifiStart = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - wifiStart < 15000UL) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("\n[WiFi] Connected. IP: %s\n", WiFi.localIP().toString().c_str());
  } else {
    Serial.println("\n[WiFi] Connection failed â€” will retry in loop.");
  }

  //NTP 
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");
  Serial.println("[NTP] Time sync requested");

  //Blynk 
  Blynk.config(BLYNK_AUTH_TOKEN);
  Blynk.connect(5000);
  Blynk.syncVirtual(V10);
  Blynk.syncVirtual(V11);
  Blynk.syncVirtual(V12);
  Serial.println("[Blynk] Connection attempted");

  //Startup beep 
  buzzerBeep(100);
  delay(100);
  buzzerBeep(100);
  digitalWrite(PIN_LED_GREEN, HIGH);

  Serial.println("[BOOT] Setup complete. Entering main loop.");
}

// ============================================================
//  MAIN LOOP non-blocking millis() scheduling
// ============================================================
void loop() {
  Blynk.run();

  unsigned long now = millis();

  // Read sensors every 500 ms 
  if (now - lastSensorMs >= INTERVAL_SENSORS) {
    lastSensorMs = now;
    readSensors();
    processMotion();
    checkGeofence();
    detectAnomalies();
    sensorFusion();
    setStatusLEDs();
  }

  // Read GPS every 1 s 
  if (now - lastGpsMs >= INTERVAL_GPS) {
    lastGpsMs = now;
    readGPS();
  }

  //Push to Blynk every 2 s
  if (now - lastBlynkMs >= INTERVAL_BLYNK) {
    lastBlynkMs = now;
    updateBlynk();
  }

  //Update baseline every 10 s 
  if (now - lastBaselineMs >= INTERVAL_BASELINE) {
    lastBaselineMs = now;
    // Accumulate for running statistics
    if (!sData.doorOpen && sData.speed_kmh < 2.0) {  // only baseline when door is closed
      baseline.sumMotion   += sData.motionMagnitude;
      baseline.sumSqMotion += sData.motionMagnitude * sData.motionMagnitude;
      baseline.count++;
      if (baseline.count >= baseline.MIN_SAMPLES) {
        baseline.mean   = baseline.sumMotion / baseline.count;
        float variance  = (baseline.sumSqMotion / baseline.count)
                          - (baseline.mean * baseline.mean);
        baseline.stdDev = (variance > 0) ? sqrt(variance) : 0.001f;
        baseline.baselineReady = true;
        Serial.printf("[BASELINE] mean=%.3f stdDev=%.3f\n",
                      baseline.mean, baseline.stdDev);
      }
    }
  }

  //Buzzer auto-off 
  if (alertState.buzzerActive && now >= alertState.buzzerStopMs) {
    digitalWrite(PIN_BUZZER, HIGH);
    alertState.buzzerActive = false;
  }

  //WiFi watchdog 
  if (now - lastWifiChkMs >= INTERVAL_WIFI_CHK) {
    lastWifiChkMs = now;
    checkWiFiReconnect();
    checkBlynkReconnect();
  }
}

// ============================================================
//  readSensors()  poll all sensors
// ============================================================
void readSensors() {
  //Reed switch (LOW = door open with INPUT_PULLUP) 
  sData.doorOpen = (digitalRead(PIN_REED_SWITCH) == LOW);

  // LDR (12-bit ADC on ESP32) 
  // LDR (12-bit ADC on ESP32) 
// REPLACEMENT: invert light logic so higher value = more light

  static int prevLight = 0;
  int rawLight = analogRead(PIN_LDR);

// invert reading because current hardware gives reverse values
  rawLight = 4095 - rawLight;

  sData.lightLevel = (0.7 * prevLight) + (0.3 * rawLight);
  prevLight = sData.lightLevel;

  // MPU6050 
  mpu.update();

  float tiltX = abs(mpu.getAngleX());
  float tiltY = abs(mpu.getAngleY());

  sData.tiltAngle = max(tiltX, tiltY);

  sData.accelX = mpu.getAccX();
  sData.accelY = mpu.getAccY();
  sData.accelZ = mpu.getAccZ();

  // ---- MOTION CALCULATION ----
  sData.motionMagnitude = sqrt(
  sData.accelX*sData.accelX +
  sData.accelY*sData.accelY +
  sData.accelZ*sData.accelZ
  );
  if(sData.motionMagnitude < 0.3){
    sData.motionMagnitude = 0;
}

// ---- TILT CALCULATION ----

  
  Serial.print("Motion: ");
  Serial.println(sData.motionMagnitude);

  Serial.print("Tilt: ");
  Serial.println(sData.tiltAngle);
  Serial.printf("[SENS] Door:%s Light:%d Ax:%.2f Ay:%.2f Az:%.2f\n",
                sData.doorOpen ? "OPEN" : "CLOSED",
                sData.lightLevel,
                sData.accelX, sData.accelY, sData.accelZ);
  if(abs(sData.tiltAngle) < 3){
    sData.tiltAngle = 0;
}
}

// ============================================================
//  readGPS() drain UART buffer, parse NMEA
// ============================================================
void readGPS() {

  static unsigned long gpsStartTime = millis();

  if (!gps.location.isValid() && millis() - gpsStartTime > 60000) {
    Serial.println("[GPS] No fix after 60 seconds");
  }

  while (gpsSerial.available() > 0) {
    char c = gpsSerial.read();
    gps.encode(c);
  }

  if (gps.location.isUpdated() && gps.location.isValid() && gps.satellites.value() >= 4) {

    sData.latitude  = gps.location.lat();
    sData.longitude = gps.location.lng();
    sData.speed_kmh = gps.speed.kmph();
    sData.gpsValid  = true;
    sData.lastGpsMs = millis();

    Serial.printf("[GPS] Lat:%.6f Lon:%.6f Speed:%.1f km/h\n",
                  sData.latitude, sData.longitude, sData.speed_kmh);

    Serial.printf("[GPS] Satellites: %d\n", gps.satellites.value());

    /* ---------- GEOFENCE INITIALIZATION ---------- */

    if (!geofenceSet) {
      refLatitude = sData.latitude;
      refLongitude = sData.longitude;
      geofenceSet = true;
      Serial.println("[GEOFENCE] Reference location set");
    }

    /* ---------- GEOFENCE CHECK ---------- */

    if (geofenceSet) {

      double distance = calculateDistance(
        refLatitude,
        refLongitude,
        sData.latitude,
        sData.longitude
      );

      Serial.print("[GEOFENCE] Distance: ");
      Serial.println(distance);

      if (distance > GEOFENCE_RADIUS) {
        logEvent("Geofence breach detected");
        handleAlerts("GEOFENCE", 2);
      }
    }

  } else {

    sData.gpsValid = false;
    Serial.println("[GPS] Waiting for satellite fix...");
  }

  // GPS signal lost detection
  if (sData.gpsValid && (millis() - sData.lastGpsMs > GPS_TIMEOUT_MS)) {

    sData.gpsValid = false;

    unsigned long now = millis();

    if (now - alertState.gpsLostAlertLast > ALERT_COOLDOWN_MS) {

      alertState.gpsLostAlertLast = now;

      logEvent("GPS signal lost");

      handleAlerts("GPS_LOST", 1);
    }
  }
}
// ============================================================
//  processMotion() tilt, movement, door, light alerts
// ============================================================
void processMotion() {
  float accelMag = sqrt(
    sData.accelX * sData.accelX +
    sData.accelY * sData.accelY +
    sData.accelZ * sData.accelZ
);

float netMotion = accelMag;

sData.motionMagnitude = netMotion;
Serial.printf("[MOTION] %.3f\n", sData.motionMagnitude);

  unsigned long now = millis();

  // Door open alert 
  if (sData.doorOpen && (now - alertState.doorAlertLast > ALERT_COOLDOWN_MS)) {
    alertState.doorAlertLast = now;
    logEvent("Door opened");
    handleAlerts("DOOR_OPEN", 2);
  }

  //Tilt alert
  if (sData.tiltAngle > TILT_THRESHOLD &&
      (now - alertState.tiltAlertLast > ALERT_COOLDOWN_MS)) {
    alertState.tiltAlertLast = now;
    char msg[64];
    snprintf(msg, sizeof(msg), "Excessive tilt: %.1f deg", sData.tiltAngle);
    logEvent(msg);
    handleAlerts("TILT", 2);
  }

  //Motion / vibration alert 
  // Compare against gravity (9.8 m/sÂ²); anything > threshold above = shock
  float netAccel = sData.motionMagnitude;
  if (netAccel > MOVEMENT_THRESHOLD &&
      (now - alertState.motionAlertLast > ALERT_COOLDOWN_MS)) {
    alertState.motionAlertLast = now;
    char msg[64];
    snprintf(msg, sizeof(msg), "Abnormal motion: %.2f m/s2", netAccel);
    logEvent(msg);
    handleAlerts("MOTION", 1);
  }

  //Light intrusion
  if (!sData.doorOpen && sData.lightLevel > LIGHT_THRESHOLD &&
      (now - alertState.lightAlertLast > ALERT_COOLDOWN_MS)) {
    alertState.lightAlertLast = now;
    char msg[64];
    snprintf(msg, sizeof(msg), "Light intrusion detected: %d", sData.lightLevel);
    logEvent(msg);
    handleAlerts("LIGHT_INTRUSION", 2);
  }
  Serial.print("Motion: ");
  Serial.println(sData.motionMagnitude);

  Serial.print("Tilt: ");
  Serial.println(sData.tiltAngle);
}


// ============================================================
//  calculateDistance()  Haversine formula (metres)
// ============================================================

double calculateDistance(double lat1, double lon1, double lat2, double lon2){

    const double R = 6371000;

    double dLat = radians(lat2 - lat1);
    double dLon = radians(lon2 - lon1);

    double a = sin(dLat/2) * sin(dLat/2) +
               cos(radians(lat1)) *
               cos(radians(lat2)) *
               sin(dLon/2) * sin(dLon/2);

    double c = 2 * atan2(sqrt(a), sqrt(1-a));

    return R * c;
 
}


// ============================================================
//  checkGeofence() distance-based route deviation
// ============================================================
void checkGeofence() {
  if (!sData.gpsValid) return;
  if (GEO_BASE_LAT == 0.0 && GEO_BASE_LON == 0.0) return;  // not configured

  double dist = calculateDistance(sData.latitude, sData.longitude,
                                  GEO_BASE_LAT, GEO_BASE_LON);

  unsigned long now = millis();
  if (dist > (GEO_RADIUS_M + 10) && (now - alertState.geoAlertLast > ALERT_COOLDOWN_MS)) {
    alertState.geoAlertLast = now;
    char msg[96];
    snprintf(msg, sizeof(msg),
             "Geofence breach! Dist: %.1f m (limit %.1f m)", dist, GEO_RADIUS_M);
    logEvent(msg);
    handleAlerts("GEOFENCE", 3);
  }
}

// ============================================================
//  detectAnomalies()  z-score based statistical detection
// ============================================================
void detectAnomalies() {
  if (!baseline.baselineReady) return;

  float z = fabs(sData.motionMagnitude - baseline.mean) / baseline.stdDev;

  if (z > ANOMALY_Z_THRESHOLD) {
    unsigned long now = millis();
    if (now - alertState.anomalyAlertLast > ALERT_COOLDOWN_MS) {
      alertState.anomalyAlertLast = now;
      char msg[80];
      snprintf(msg, sizeof(msg),
               "Statistical anomaly! z-score=%.2f (thresh=%.1f)", z, ANOMALY_Z_THRESHOLD);
      logEvent(msg);
      handleAlerts("ANOMALY", 2);
    }
  }
}

// ============================================================
//  sensorFusion() multi-sensor risk scoring
// ============================================================
void sensorFusion() {
  float score = 0;

  // Individual risk weights
  if (sData.doorOpen)                                 score += 30;
  if (sData.tiltAngle > TILT_THRESHOLD)               score += 20;
  float netAccel = fabs(sData.motionMagnitude - 9.81f);
  if (netAccel > MOVEMENT_THRESHOLD)                  score += 20;
  if (!sData.doorOpen && sData.lightLevel > LIGHT_THRESHOLD) score += 25;
  if (!sData.gpsValid)                                score += 10;

  // Compound scenario bonuses
  if (sData.doorOpen && netAccel > MOVEMENT_THRESHOLD) {
    score += 15;  // door open + motion = high risk
    logEvent("FUSION: Door open + motion detected");
  }
  if (sData.doorOpen && sData.lightLevel > LIGHT_THRESHOLD) {
    score += 20;  // container breach scenario
  }

  sData.riskScore = min(score, 100.0f);

  // Determine security level
  if      (sData.riskScore >= 75) sData.securityLevel = 3;  // CRITICAL
  else if (sData.riskScore >= 50) sData.securityLevel = 2;  // ALERT
  else if (sData.riskScore >= 25) sData.securityLevel = 1;  // WARNING
  else                            sData.securityLevel = 0;  // OK

  Serial.printf("[FUSION] Risk:%.0f Level:%d\n",
                sData.riskScore, sData.securityLevel);
}

// ============================================================
//  updateBlynk() â€” push all data to dashboard
// ============================================================
void updateBlynk() {
  if (!Blynk.connected()) return;

  Blynk.virtualWrite(VPIN_DOOR,      sData.doorOpen ? 1 : 0);
  Blynk.virtualWrite(VPIN_TILT,      sData.tiltAngle);
  Blynk.virtualWrite(VPIN_MOTION,    sData.motionMagnitude);
  Blynk.virtualWrite(VPIN_LIGHT,     sData.lightLevel);
  Blynk.virtualWrite(VPIN_GPS_SPEED, sData.speed_kmh);
  Blynk.virtualWrite(VPIN_SECURITY,  sData.securityLevel);
  Blynk.virtualWrite(VPIN_RISK_SCORE, sData.riskScore);

  // Send GPS map location
  if (sData.gpsValid) {
    Blynk.virtualWrite(VPIN_LATITUDE,  sData.latitude);
    Blynk.virtualWrite(VPIN_LONGITUDE, sData.longitude);
  }

  Serial.printf("[BLYNK] Data pushed. Risk:%.0f Sec:%d\n",
                sData.riskScore, sData.securityLevel);
}

// ============================================================
//  handleAlerts() buzzer + Blynk notification
//  level: 1=INFO, 2=WARNING, 3=CRITICAL
// ============================================================
void handleAlerts(const char* reason, int level) {
  Serial.printf("[ALERT] %s (level %d)\n", reason, level);

  Serial.println(reason);
  if(level == 1){
      Blynk.logEvent("warning_alert", reason);
  }
}

void logEvent(const char* event) {
  Serial.print("[EVENT] ");
  Serial.println(event);

  if (Blynk.connected()) {
    Blynk.virtualWrite(VPIN_EVENT_LOG, event);
  }
}

void buzzerBeep(int durationMs) {
  digitalWrite(PIN_BUZZER, LOW);
  delay(durationMs);
  digitalWrite(PIN_BUZZER, HIGH);
}

void setStatusLEDs() {

  if (sData.securityLevel == 0) {
    digitalWrite(PIN_LED_GREEN, HIGH);
    digitalWrite(PIN_LED_RED, LOW);
  }

  else if (sData.securityLevel == 1) {
    digitalWrite(PIN_LED_GREEN, HIGH);
    digitalWrite(PIN_LED_RED, HIGH);
  }

  else {
    digitalWrite(PIN_LED_GREEN, LOW);
    digitalWrite(PIN_LED_RED, HIGH);
  }

}

void checkWiFiReconnect() {

  if (WiFi.status() != WL_CONNECTED) {

    Serial.println("[WiFi] Reconnecting...");

    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  }

}

void checkBlynkReconnect() {

  if (!Blynk.connected()) {

    Serial.println("[Blynk] Reconnecting...");

    Blynk.connect();

  }

}