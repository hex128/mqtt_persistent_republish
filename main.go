package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"log"
	"os"
	"strings"
)

func main() {
	srcMqttHost := os.Getenv("SRC_HOST")
	srcMqttPort := os.Getenv("SRC_PORT")
	srcMqttUser := os.Getenv("SRC_USER")
	srcMqttPass := os.Getenv("SRC_PASS")
	srcMqttTLS := os.Getenv("SRC_TLS")
	srcTLSCA := os.Getenv("SRC_TLS_CA")
	srcTLSCert := os.Getenv("SRC_TLS_CERT")
	srcTLSKey := os.Getenv("SRC_TLS_KEY")
	srcPrefix := os.Getenv("SRC_PREFIX")

	dstMqttHost := os.Getenv("DST_HOST")
	dstMqttPort := os.Getenv("DST_PORT")
	dstMqttUser := os.Getenv("DST_USER")
	dstMqttPass := os.Getenv("DST_PASS")
	dstMqttTLS := os.Getenv("DST_TLS")
	dstTLSCA := os.Getenv("DST_TLS_CA")
	dstTLSCert := os.Getenv("DST_TLS_CERT")
	dstTLSKey := os.Getenv("DST_TLS_KEY")
	dstPrefix := os.Getenv("DST_PREFIX")

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
	if srcMqttPort == "8883" || srcMqttTLS == "1" {
		srcBroker = fmt.Sprintf("ssl://%s:%s", srcMqttHost, srcMqttPort)
		srcOpts.SetTLSConfig(&srcTlsConfig)
	}
	srcOpts.AddBroker(srcBroker)
	if srcMqttUser != "" && srcMqttPass != "" {
		srcOpts.SetUsername(srcMqttUser)
		srcOpts.SetPassword(srcMqttPass)
	}

	dstOpts := mqtt.NewClientOptions()
	dstBroker := fmt.Sprintf("tcp://%s:%s", dstMqttHost, dstMqttPort)
	if dstMqttPort == "8883" || dstMqttTLS == "1" {
		dstBroker = fmt.Sprintf("ssl://%s:%s", dstMqttHost, dstMqttPort)
		dstOpts.SetTLSConfig(&dstTlsConfig)
	}
	dstOpts.AddBroker(dstBroker)
	if dstMqttUser != "" && dstMqttPass != "" {
		dstOpts.SetUsername(dstMqttUser)
		dstOpts.SetPassword(dstMqttPass)
	}

	srcClient := mqtt.NewClient(srcOpts)
	if token := srcClient.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	dstClient := mqtt.NewClient(dstOpts)
	if token := dstClient.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	srcClient.Subscribe(srcPrefix+"#", 0, func(client mqtt.Client, msg mqtt.Message) {
		newTopic := dstPrefix + strings.TrimPrefix(msg.Topic(), srcPrefix)
		token := dstClient.Publish(newTopic, msg.Qos(), true, msg.Payload())
		token.Wait()
	})

	select {}
}
