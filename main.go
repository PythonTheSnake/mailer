package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/bitly/go-nsq"
	r "github.com/dancannon/gorethink"
	"github.com/getsentry/raven-go"
	"github.com/hashicorp/golang-lru"
	"github.com/lavab/go-spamc"
	"github.com/namsral/flag"

	"github.com/lavab/mailer/models"
)

var (
	// Enable config file loading
	configFlag = flag.String("config", "", "Config file to load")

	// Sentry crash reporting
	ravenDSN = flag.String("raven_dsn", "", "DSN of the Raven connection")

	// RethinkDB connection settings
	rethinkdbAddress  = flag.String("rethinkdb_address", "127.0.0.1:28015", "Address of the RethinkDB database")
	rethinkdbDatabase = flag.String("rethinkdb_db", "prod", "Database name on the RethinkDB server")

	// nsqd and nsqlookupd addresses
	nsqdAddress    = flag.String("nsqd_address", "127.0.0.1:4150", "Address of the nsqd server")
	lookupdAddress = flag.String("lookupd_address", "127.0.0.1:4161", "Address of the lookupd server")

	// Handler settings
	bindAddresses  = flag.String("handler_addresses", ":25,:587", "Addresses used to bind the handler")
	welcomeMessage = flag.String("handler_welcome", "Welcome to Lavaboom!", "Welcome message displayed upon connecting to the server.")
	hostname       = flag.String("handler_hostname", "localhost", "Hostname of the mailer")
	readTimeout    = flag.Int("handler_read_timeout", 0, "Connection read timeout expressed in seconds")
	writeTimeout   = flag.Int("handler_write_timeout", 0, "Connection write timeout expressed in seconds")
	dataTimeout    = flag.Int("handler_data_timeout", 0, "Data stream timeout expressed in seconds")
	maxConnections = flag.Int("handler_max_connections", 0, "Max connections that can be handled by the mailer")
	maxMessageSize = flag.Int("handler_max_message_size", 0, "Max message size accepted by the mailer in bytes")
	maxRecipients  = flag.Int("handler_max_recipients", 0, "Max recipients count per envelope")
	enableTLS      = flag.Bool("handler_enable_tls", false, "Enable STARTTLS?")
	tlsCertificate = flag.String("handler_tls_cert", "", "Path of the TLS certificate to load")
	tlsKey         = flag.String("handler_tls_key", "", "Path of the TLS key to load")
	spamdAddress   = flag.String("spamd_address", "127.0.0.1:783", "Address of the spamd server to use")

	// Outbound email handling settings
	smtpdAddress        = flag.String("smtpd_address", "127.0.0.1:2525", "Address of the SMTP relay to use")
	dkimLRUSize         = flag.Int("dkim_lru_size", 128, "Size of the LRU cache with DKIM keys")
	consumerConcurrency = flag.Int("consumer_concurrency", 10, "Concurrency of the consumer that sends out emails")
)

var (
	stdLogger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)
)

func main() {
	flag.Parse()

	// Create a new Raven client
	var rc *raven.Client
	if *ravenDSN != "" {
		h, err := os.Hostname()
		if err != nil {
			log.Fatal(err)
		}

		rc, err = raven.NewClient(*ravenDSN, map[string]string{
			"hostname": h,
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	defer capturePanic(rc)

	// Connect to RethinkDB
	session, err := r.Connect(r.ConnectOpts{
		Address: *rethinkdbAddress,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create mailer-specific tables
	r.DB(*rethinkdbDatabase).TableCreate("dkim_keys").Exec(session)

	// Create a LRU cache with DKIM signers
	dc, err := lru.New(*dkimLRUSize)
	if err != nil {
		log.Fatal(err)
	}

	// Clear all changed keys when they change
	go func() {
		cursor, err := r.DB(*rethinkdbDatabase).Table("dkim_keys").Changes().Run(session)
		if err != nil {
			log.Fatal(err)
		}
		var change struct {
			NewValue *models.DKIMKey `gorethink:"new_val"`
			OldValue *models.DKIMKey `gorethink:"old_val"`
		}
		for cursor.Next(&change) {
			if change.OldValue != nil {
				dc.Remove(change.OldValue.ID)
			}

			if change.OldValue == nil && change.NewValue != nil {
				dc.Remove(change.NewValue.ID)
			}
		}
		if err := cursor.Err(); err != nil {
			log.Fatal(err)
		}
	}()

	// Create a new NSQ producer
	producer, err := nsq.NewProducer(*nsqdAddress, nsq.NewConfig())
	if err != nil {
		log.Fatal(err)
	}
	producer.SetLogger(stdLogger, nsq.LogLevelWarning)

	// Create a new NSQ consumer
	consumer, err := nsq.NewConsumer("send_email", "receive", nsq.NewConfig())
	if err != nil {
		log.Fatal(err)
	}
	consumer.SetLogger(stdLogger, nsq.LogLevelWarning)
	consumer.AddConcurrentHandlers(&outbound{
		SmtpdAddress: *smtpdAddress,
		DKIM:         dc,
		Raven:        rc,
		RethinkDB:    session,
	}, *consumerConcurrency)
	if err := consumer.ConnectToNSQLookupd(*lookupdAddress); err != nil {
		log.Fatal(err)
	}

	// Connect to spamd
	spam := spamc.New(*spamdAddress, 10)

	// Load TLS cert and key
	var tlsConfig *tls.Config
	if *enableTLS {
		cert, err := ioutil.ReadFile(*tlsCertificate)
		if err != nil {
			log.Fatal(err)
		}

		key, err := ioutil.ReadFile(*tlsKey)
		if err != nil {
			log.Fatal(err)
		}

		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			log.Fatal(err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{pair},
		}
	}

	// Create a handler
	h := &handler{
		WelcomeMessage: *welcomeMessage,
		Hostname:       *hostname,
		ReadTimeout:    *readTimeout,
		WriteTimeout:   *writeTimeout,
		DataTimeout:    *dataTimeout,
		MaxConnections: *maxConnections,
		MaxMessageSize: *maxMessageSize,
		MaxRecipients:  *maxRecipients,

		TLSConfig: tlsConfig,
		RethinkDB: session,
		Producer:  producer,
		Raven:     rc,
		Spam:      spam,
	}

	// Split bind addresses and serve them
	addresses := strings.Split(*bindAddresses, ",")
	for i := 0; i < len(addresses)-1; i++ {
		go func(address string) {
			log.Printf("Listening to %s", address)
			if err := h.ListenAndServe(address); err != nil {
				log.Fatal(err)
			}
		}(addresses[i])
	}
	log.Printf("Listening to %s", addresses[len(addresses)-1])
	if err := h.ListenAndServe(addresses[len(addresses)-1]); err != nil {
		log.Fatal(err)
	}
}
