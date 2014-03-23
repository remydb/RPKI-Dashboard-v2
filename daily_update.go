package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
)

type RouteObject struct {
	Id       bson.ObjectId `bson:"_id,omitempty" json:"_id"`
	ASN      string        `bson:"asn" json:"asn"`
	Prefix   string        `bson:"prefix" json:"prefix"`
	Validity int8          `bson:"validity" json:"validity"`
	RIR      string        `bson:"rir" json:"rir"`
	VRP      string        `bson:"vrp" json:"vrp"`
	IPver    uint8         `bson:"ipver" json:"ipver"`
	Binary   string        `bson:"binary" json:"binary"`
}

func (self *RouteObject) Init() {
	self.Id = bson.NewObjectId()
}

type RoaObject struct {
	Id     bson.ObjectId `bson:"_id,omitempty" json:"_id"`
	ASN    string        `bson:"asn" json:"asn"`
	Prefix string        `bson:"prefix" json:"prefix"`
	Maxlen string        `bson:"maxlen" json:"maxlen"`
	Binary string        `bson:"binary" json:"binary"`
}

func (self *RoaObject) Init() {
	self.Id = bson.NewObjectId()
}

const maxGoRoutines = 20

var (
	mconn    *mgo.Session
	cname    string = time.Now().Format("2006-01-02")
	err      error
	throttle = make(chan int, maxGoRoutines)

	//Route validity states:
	fixed_length_exceeded   int8 = 1
	range_length_exceeded   int8 = 2
	asn_mismatch            int8 = 3
	asn_and_length_mismatch int8 = 4
	valid                   int8 = 0
	unknown                 int8 = -1
)

func ipToBin(IP string) (result string, ipver uint8) {
	if strings.Contains(IP, ".") {
		parse := net.ParseIP(IP).To4()
		result = fmt.Sprintf("%08b%08b%08b%08b", parse[0], parse[1], parse[2], parse[3])
		ipver = 4
	} else if strings.Contains(IP, ":") {
		parse := net.ParseIP(IP).To16()
		result = fmt.Sprintf("%016b%016b%016b%016b%016b%016b%016b%016b", parse[0], parse[1], parse[2], parse[3], parse[4], parse[5], parse[6], parse[7])
		ipver = 6
	}
	return result, ipver
}

func ipToBinShort(IP string, length int) (result string, ipver uint8) {
	if strings.Contains(IP, ".") {
		parse := net.ParseIP(IP).To4()
		result = fmt.Sprintf("%08b%08b%08b%08b", parse[0], parse[1], parse[2], parse[3])
		ipver = 4
	} else if strings.Contains(IP, ":") {
		parse := net.ParseIP(IP).To16()
		result = fmt.Sprintf("%016b%016b%016b%016b%016b%016b%016b%016b", parse[0], parse[1], parse[2], parse[3], parse[4], parse[5], parse[6], parse[7])
		ipver = 6
	}
	result = result[:length]
	return result, ipver
}

func parseRisDump(geturl string) (err error) {
	colname := fmt.Sprintf("%s-routes", cname)
	cloneconn := mconn.Clone()
	defer cloneconn.Clone()
	c := cloneconn.DB("rpki_dash").C(colname)
	fmt.Println("Downloading RIS dump...")

	lines, err := getUrl(geturl)
	if err != nil {
		log.Fatal("Download failed: %s", err)
	}

	var wg sync.WaitGroup
	fmt.Println("Processing RIS dump...")
	for i := range lines {
		throttle <- 1
		wg.Add(1)
		fmt.Printf("\rStart processing route number %d", i)
		go func(i int) {
			defer wg.Done()
			rconn := mconn.Clone()
			defer rconn.Close()
			rconn_routes := rconn.DB("rpki_dash").C(colname)
			if result, _ := regexp.MatchString("^[0-9]+", lines[i]); result == true {
				robj := strings.Split(lines[i], "\t")
				seen, err := strconv.Atoi(robj[2])
				if err != nil {
					log.Fatalf("Failed to convert str to int: %s", err)
				}
				if seen < 5 {
					//Here we skip all the routes seen by less than 5 ris peers
					<-throttle
					return
				}
				sprefix := strings.Split(robj[1], "/")
				binary, ipver := ipToBin(sprefix[0])
				jsonobj := &RouteObject{
					ASN:      robj[0],
					Prefix:   robj[1],
					Validity: unknown,
					RIR:      "",
					VRP:      "",
					IPver:    ipver,
					Binary:   binary,
				}
				err = rconn_routes.Insert(&jsonobj)
				if err != nil {
					log.Fatalf("Failed MongoDB insert: %s", err)
				}

			}
			<-throttle
			return
		}(i)
	}
	wg.Wait()

	err = c.EnsureIndexKey("binary", "prefix")
	if err != nil {
		log.Fatalf("Failed to set indexes: %s", err)
	}
	fmt.Printf("\nFinished processing RIS dump\n")
	return nil
}

func parseRoaList(geturl string) (err error) {
	colname := fmt.Sprintf("%s-vrp", cname)
	cloneconn := mconn.Clone()
	defer cloneconn.Close()
	c := cloneconn.DB("rpki_dash").C(colname)
	c.DropCollection()

	lines, err := getUrl(geturl)
	if err != nil {
		log.Fatal("Download failed: %s", err)
	}

	var wg sync.WaitGroup
	fmt.Println("Processing VRP...")
	for i := range lines {
		throttle <- 1
		wg.Add(1)
		fmt.Printf("\rStart processing line %d", i)
		go func(i int) {
			defer wg.Done()
			if !strings.HasPrefix(lines[i], "ASN,IP") {
				vrpobj := strings.Split(lines[i], ",")
				vrpobj[0] = strings.Trim(vrpobj[0], "AS")
				vrpobj[2] = strings.Trim(vrpobj[2], "\n")
				sprefix := strings.Split(vrpobj[1], "/")
				length, err := strconv.Atoi(sprefix[1])
				if err != nil {
					log.Fatalf("Failed to convert str to int: %s", err)
				}
				binary, _ := ipToBinShort(sprefix[0], length)
				jsonobj := RoaObject{
					ASN:    vrpobj[0],
					Prefix: vrpobj[1],
					Maxlen: vrpobj[2],
					Binary: binary,
				}
				err = c.Insert(&jsonobj)
				if err != nil {
					log.Fatalf("Failed MongoDB insert: %s", err)
					<-throttle
				}
			}
			<-throttle
		}(i)
	}
	wg.Wait()
	err = c.EnsureIndexKey("binary", "prefix")
	if err != nil {
		log.Fatalf("Failed to set indexes: %s", err)
	}
	fmt.Printf("\nFinished processing VRP\n")
	return nil
}

func validateRoutes() (err error) {
	colname_vrp := fmt.Sprintf("%s-vrp", cname)
	colname_routes := fmt.Sprintf("%s-routes", cname)
	con_vrp := mconn.Clone().DB("rpki_dash").C(colname_vrp)
	defer mconn.DB("rpki_dash").Session.Close()
	roas := []RoaObject{}
	iter := con_vrp.Find(nil).Iter()
	err = iter.All(&roas)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for i := range roas {
		throttle <- 1
		wg.Add(1)
		fmt.Printf("\rStarting routine %d", i)
		go func(i int) {
			defer wg.Done()
			rconn := mconn.Clone()
			defer rconn.Close()
			rconn_routes := rconn.DB("rpki_dash").C(colname_routes)
			binsearch := fmt.Sprintf("^%s", roas[i].Binary)
			regex := bson.RegEx{binsearch, ""}
			query := bson.M{"binary": regex}
			routes := []RouteObject{}
			err = rconn_routes.Find(query).Iter().All(&routes)
			if err != nil {
				log.Fatalf("Error fetching matching routes: %s", err)
			}
			roa_length := len(roas[i].Binary)
			roa_maxlen, err := strconv.Atoi(roas[i].Maxlen)
			if err != nil {
				log.Fatalf("Failed to convert ROA length to int: %s", err)
			}
			for x := range routes {
				route_length := len(routes[x].Binary)
				if route_length >= roa_length && route_length <= roa_maxlen && routes[x].ASN == roas[i].ASN {
					routes[x].Validity = valid
				} else {
					if routes[x].ASN == roas[i].ASN && route_length > roa_maxlen {
						if routes[x].Validity != valid {
							if roa_length == roa_maxlen {
								routes[x].Validity = fixed_length_exceeded
							} else {
								routes[x].Validity = range_length_exceeded
							}
						}
					} else if routes[x].ASN != roas[i].ASN && route_length >= roa_length && route_length <= roa_maxlen {
						if routes[x].Validity != valid {
							routes[x].Validity = asn_mismatch
						}
					} else if routes[x].ASN != roas[i].ASN && route_length > roa_maxlen {
						if routes[x].Validity != valid {
							routes[x].Validity = asn_and_length_mismatch
						}
					}
				}
				routes[x].VRP += roas[i].Id.String() + ","
				query_param := bson.M{"_id": routes[x].Id}
				change := bson.M{"$set": bson.M{"validity": routes[x].Validity, "vrp": routes[x].VRP}}
				_, err = rconn_routes.UpdateAll(query_param, change)
				if err != nil {
					log.Fatalf("Failed to update route validity status in MongoDB: %s", err)
				}
			}
			<-throttle
		}(i)
	}
	wg.Wait()
	return nil
}

func setEnv() {
	procs := runtime.NumCPU()
	runtime.GOMAXPROCS(procs)
	fmt.Printf("GOMAXPROCS: %d\n", procs)
}

func getUrl(url string) (lines []string, err error) {
	fmt.Println("Starting file download:", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	var body io.Reader
	if strings.HasSuffix(url, ".gz") {
		body, err = gzip.NewReader(resp.Body)
		if err != nil {
			log.Fatalf("Failed to read response: %s", err)
		}
	} else {
		body = resp.Body
	}

	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("File download finished")

	return lines, err
}

func getCsv(url string) (lines [][]string, err error) {
	fmt.Println("Starting file download:", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	reader := csv.NewReader(resp.Body)
	lines, err = reader.ReadAll()
	if err != nil {
		log.Fatalf("Failed to read csv file: %s", err)
		return nil, err
	}
	return lines, nil
}

func insertRirs(geturlv4 string, geturlv6 string) (err error) {
	lines, err := getCsv(geturlv4)
	if err != nil {
		log.Fatal("Download failed: %s", err)
	}

	colname_routes := fmt.Sprintf("%s-routes", cname)

	var wg sync.WaitGroup

	fmt.Println("Adding RIRs for IPv4 routes...")
	for i := range lines {
		throttle <- 1
		wg.Add(1)
		fmt.Printf("\rStart processing line %d", i)
		//fmt.Printf("Prefix: %s\tWhois: %s\n", lines[i][0], lines[i][3])
		go func(i int) {
			defer wg.Done()
			if match, _ := regexp.MatchString("^[0-9]{3}/[0-9]{1,2}", lines[i][0]); match == true {
				if match, _ = regexp.MatchString("whois.[a-z]*.[a-z]*", lines[i][3]); match != true {
					<-throttle
					return
				}
				rir := strings.Split(lines[i][3], ".")
				lenpart := strings.Split(lines[i][0], "/")
				prefix, err := strconv.Atoi(lenpart[0])
				if err != nil {
					log.Fatalf("Failed to convert str to int: %s", err)
				}
				rconn := mconn.Clone()
				defer rconn.Close()
				rconn_routes := rconn.DB("rpki_dash").C(colname_routes)
				search := fmt.Sprintf("^%d", prefix)
				regex := bson.RegEx{search, ""}
				query_param := bson.M{"ipver": 4, "prefix": regex}
				change := bson.M{"$set": bson.M{"rir": rir[1]}}
				_, err = rconn_routes.UpdateAll(query_param, change)
				if err != nil {
					log.Fatalf("Failed to update rir in MongoDB: %s", err)
				}
			}
			<-throttle
		}(i)
	}
	wg.Wait()
	fmt.Printf("\nFinished processing RIRs for IPv4\n")

	lines, err = getCsv(geturlv6)
	if err != nil {
		log.Fatal("Download failed: %s", err)
	}

	fmt.Println("Adding RIRs for IPv6 routes...")
	for i := range lines {
		throttle <- 1
		wg.Add(1)
		fmt.Printf("\rStart processing line %d", i)
		go func(i int) {
			defer wg.Done()
			if match, _ := regexp.MatchString("^[0-9a-f]{4}[:0-9a-f]*/[0-9]{1,3}", lines[i][0]); match == true {
				if match, _ = regexp.MatchString("whois.[a-z]*.[a-z]*", lines[i][3]); match != true {
					<-throttle
					return
				}
				rir := strings.Split(lines[i][3], ".")
				lenpart := strings.Split(lines[i][0], "/")
				length, err := strconv.Atoi(lenpart[1])
				if err != nil {
					log.Fatalf("Failed to convert str to int: %s", err)
				}
				binary, _ := ipToBinShort(lenpart[0], length)
				rconn := mconn.Clone()
				defer rconn.Close()
				rconn_routes := rconn.DB("rpki_dash").C(colname_routes)
				binsearch := fmt.Sprintf("^%s", binary)
				regex := bson.RegEx{binsearch, ""}
				query_param := bson.M{"ipver": 6, "binary": regex}
				change := bson.M{"$set": bson.M{"rir": rir[1]}}
				_, err = rconn_routes.UpdateAll(query_param, change)
				if err != nil {
					log.Fatalf("Failed to update rir in MongoDB: %s", err)
				}
			}
			<-throttle
		}(i)
	}
	wg.Wait()
	fmt.Printf("\nFinished processing RIRs for IPv6\n")
	return nil
}

func main() {
	setEnv()
	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("Started at: %s\n", now)
	mconn, err = mgo.Dial("localhost")
	if err != nil {
		log.Fatalf("Failed to connect to Mongodb: %s", err)
	}
	defer mconn.Close()

	//Mainly for testing purposes, delete all collections on start
	// vrpcollection := fmt.Sprintf("%s-vrp", cname)
	// routecollection := fmt.Sprintf("%s-routes", cname)
	// mconn.DB("rpki_dash").C(vrpcollection).DropCollection()
	// mconn.DB("rpki_dash").C(routecollection).DropCollection()

	err = parseRoaList("http://rpki.surfnet.nl:8080/export.csv")
	if err != nil {
		log.Fatalf("Failed to process ROAs: %s", err)
	}
	err = parseRisDump("http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz")
	if err != nil {
		log.Fatalf("Failed to process IPv4 routes: %s", err)
	}
	err = parseRisDump("http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz")
	if err != nil {
		log.Fatalf("Failed to process IPv6 routes: %s", err)
	}
	err = validateRoutes()
	if err != nil {
		log.Fatalf("Failed to validate routes: %s", err)
	}
	err = insertRirs("http://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv",
		"http://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv")
	if err != nil {
		log.Fatalf("Failed to insert rirs: %s", err)
	}
	now = time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("Finished at: %s\n", now)
}
