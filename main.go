package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	srcMqttHost := os.Getenv("SRC_HOST")
	srcMqttPort := os.Getenv("SRC_PORT")
	srcClientID := os.Getenv("SRC_CLIENT_ID")
	srcMqttUser := os.Getenv("SRC_USER")
	srcMqttPass := os.Getenv("SRC_PASS")
	srcMqttTLS := os.Getenv("SRC_TLS") == "1"
	srcTLSCA := os.Getenv("SRC_TLS_CA")
	srcTLSCert := os.Getenv("SRC_TLS_CERT")
	srcTLSKey := os.Getenv("SRC_TLS_KEY")
	srcPrefix := os.Getenv("SRC_PREFIX")
	srcIgnoreRetained := os.Getenv("SRC_IGNORE_RETAINED") == "1"

	dstMqttHost := os.Getenv("DST_HOST")
	dstMqttPort := os.Getenv("DST_PORT")
	dstClientID := os.Getenv("DST_CLIENT_ID")
	dstMqttUser := os.Getenv("DST_USER")
	dstMqttPass := os.Getenv("DST_PASS")
	dstMqttTLS := os.Getenv("DST_TLS") == "1"
	dstTLSCA := os.Getenv("DST_TLS_CA")
	dstTLSCert := os.Getenv("DST_TLS_CERT")
	dstTLSKey := os.Getenv("DST_TLS_KEY")
	dstPrefix := os.Getenv("DST_PREFIX")
	dstForceRetain := os.Getenv("DST_FORCE_RETAIN") == "1"

	if srcMqttHost == "" || dstMqttHost == "" {
		log.Fatalf("Environment variables SRC_HOST and DST_HOST must be set")
	}
	if srcMqttPort == "" {
		srcMqttPort = "1883"
	}
	if dstMqttPort == "" {
		dstMqttPort = "1883"
	}

	srcTlsConfig := tls.Config{}
	dstTlsConfig := tls.Config{}

	if srcTLSCA != "" {
		caCert, err := os.ReadFile(srcTLSCA)
		if err != nil {
			log.Fatalf("Couldn't load CA file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		srcTlsConfig.RootCAs = caCertPool
	}

	if srcTLSCert != "" && srcTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(srcTLSCert, srcTLSKey)
		if err != nil {
			log.Fatalf("Couldn't load client cert and key: %v", err)
		}
		srcTlsConfig.Certificates = []tls.Certificate{cert}
	}

	if dstTLSCA != "" {
		caCert, err := os.ReadFile(dstTLSCA)
		if err != nil {
			log.Fatalf("Couldn't load CA file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		dstTlsConfig.RootCAs = caCertPool
	}

	if dstTLSCert != "" && dstTLSKey != "" {
		cert, err := tls.LoadX509KeyPair(dstTLSCert, dstTLSKey)
		if err != nil {
			log.Fatalf("Couldn't load client cert and key: %v", err)
		}
		dstTlsConfig.Certificates = []tls.Certificate{cert}
	}

	srcOpts := mqtt.NewClientOptions()
	srcBroker := fmt.Sprintf("tcp://%s:%s", srcMqttHost, srcMqttPort)
	if srcMqttPort == "8883" || srcMqttTLS {
		srcBroker = fmt.Sprintf("ssl://%s:%s", srcMqttHost, srcMqttPort)
		srcOpts.SetTLSConfig(&srcTlsConfig)
	}
	srcOpts.AddBroker(srcBroker)
	srcOpts.SetAutoReconnect(true)
	srcOpts.SetConnectRetry(true)
	srcOpts.SetKeepAlive(15 * time.Second)
	if srcClientID != "" {
		srcOpts.SetClientID(srcClientID)
		srcOpts.SetCleanSession(false)
	}
	if srcMqttUser != "" && srcMqttPass != "" {
		srcOpts.SetUsername(srcMqttUser)
		srcOpts.SetPassword(srcMqttPass)
	}

	dstOpts := mqtt.NewClientOptions()
	dstBroker := fmt.Sprintf("tcp://%s:%s", dstMqttHost, dstMqttPort)
	if dstMqttPort == "8883" || dstMqttTLS {
		dstBroker = fmt.Sprintf("ssl://%s:%s", dstMqttHost, dstMqttPort)
		dstOpts.SetTLSConfig(&dstTlsConfig)
	}
	dstOpts.AddBroker(dstBroker)
	dstOpts.SetAutoReconnect(true)
	dstOpts.SetConnectRetry(true)
	dstOpts.SetKeepAlive(15 * time.Second)
	if dstClientID != "" {
		dstOpts.SetClientID(dstClientID)
		dstOpts.SetCleanSession(false)
	}
	if dstMqttUser != "" && dstMqttPass != "" {
		dstOpts.SetUsername(dstMqttUser)
		dstOpts.SetPassword(dstMqttPass)
	}

	dstOpts.SetOnConnectHandler(func(client mqtt.Client) {
		log.Printf("Connected to %s", dstBroker)
	})
	dstOpts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		log.Printf("Connection to %s lost: %v", dstBroker, err)
	})
	dstClient := mqtt.NewClient(dstOpts)

	srcOpts.SetOnConnectHandler(func(client mqtt.Client) {
		log.Printf("Connected to %s", srcBroker)
		log.Printf("Subscribing to %s/%s", srcBroker, srcPrefix+"#")
		token := client.Subscribe(srcPrefix+"#", 0, func(client mqtt.Client, msg mqtt.Message) {
			if srcIgnoreRetained && msg.Retained() {
				log.Printf("Ignoring retained message on %s/%s", srcBroker, msg.Topic())
				return
			}
			log.Printf("Received message on %s/%s retained=%v", srcBroker, msg.Topic(), msg.Retained())
			retained := dstForceRetain || msg.Retained()
			newTopic := dstPrefix + strings.TrimPrefix(msg.Topic(), srcPrefix)
			log.Printf("Republishing message to %s/%s retained=%v", dstBroker, newTopic, retained)
			token := dstClient.Publish(newTopic, msg.Qos(), retained, msg.Payload())
			token.Wait()
			if token.Error() != nil {
				log.Printf("Error publishing message to %s/%s: %v", dstBroker, newTopic, token.Error())
			}
			log.Printf("Message published to %s/%s", dstBroker, newTopic)
		})
		token.Wait()
		if token.Error() != nil {
			panic(token.Error())
		}
		log.Printf("Subscribed to %s/%s", srcBroker, srcPrefix+"#")
	})
	srcOpts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		log.Printf("Connection to %s lost: %v", srcBroker, err)
	})
	srcClient := mqtt.NewClient(srcOpts)

	log.Printf("Connecting to %s", srcBroker)
	if token := srcClient.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	log.Printf("Connecting to %s", dstBroker)
	if token := dstClient.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	select {}
}
