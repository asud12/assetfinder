package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"reflect"
    "runtime"
)

func main() {

	var subsOnly bool
	flag.BoolVar(&subsOnly, "subs-only", false, "Only include subdomains of search domain")
	flag.Parse()

	var domains io.Reader
	domains = os.Stdin

	domain := flag.Arg(0)
	if domain != "" {
		domains = strings.NewReader(domain)
	}

	sources := []fetchFn{
		fetchCertSpotter,
		fetchHackerTarget,
		fetchThreatCrowd,
		fetchCrtSh,
		fetchFacebook,
		fetchWayback,
		fetchVirusTotal,
		fetchFindSubDomains,
		fetchUrlscan,
		fetchBufferOverrun,
	}

	
	out := make(chan string)
	var wg sync.WaitGroup

	sc := bufio.NewScanner(domains)
	rl := newRateLimiter(time.Second)

	for sc.Scan() {

		domain := strings.ToLower(sc.Text())

		// call each of the source workers in a goroutine
		for _, source := range sources {
			wg.Add(1)
			fn := source

			
			// Get functionname e.g. fetchCertSoitter, split after "fetch"
			source := strings.Split(GetFunctionName(fn), "fetch")

			go func() {
				defer wg.Done()

				rl.Block(fmt.Sprintf("%#d", fn))
				names, err := fn(domain)

				if err != nil {
					//fmt.Fprintf(os.Stderr, "err: %s\n", err)
					return
				}

				for _, n := range names {
					var b []byte


					n = cleanDomain(n)
					if subsOnly && !strings.HasSuffix(n, domain) {
						continue
					}



					/* 
					* crt.sh sometimes returns multiple subdoimains split by  \n e.g. "az-sbx-bi.deloitte.co.uk\nsbx-bi.deloitte.co.uk". 
					* This obv breaks the json encoding, so need this check. 
					*/
					if strings.Contains(n, "\n"){
						
						parts := strings.Split(n, "\n")

						for _, part := range parts {
							jsonResult := &Result{Host:part,Input:domain,Source:source[1]}
							b, err = json.Marshal(jsonResult)
							
							if err != nil {
								fmt.Printf("Error: %s", err)
								return;
							}

							out <- string(b)
						} 					
					} else {
						jsonResult := &Result{Host:n,Input:domain,Source:source[1]}
						b, err = json.Marshal(jsonResult)
						if err != nil {
							fmt.Printf("Error: %s", err)
							return;
						}

						out <- string(b)
					}
				}
			}()
		}
	}

	// close the output channel when all the workers are done
	go func() {
		wg.Wait()
		close(out)
	}()

	// track what we've already printed to avoid duplicates
	printed := make(map[string]bool)

	for n := range out {
		if _, ok := printed[n]; ok {
			continue
		}
		printed[n] = true

		fmt.Println(n)
	}
}

type Result struct {
    Host string `json:"host"`
	Input string `json:"input"`
	Source string `json:"source"`
}

func GetFunctionName(i interface{}) string {
    return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

type fetchFn func(string) ([]string, error)



func httpGet(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	raw, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return []byte{}, err
	}

	return raw, nil
}

func cleanDomain(d string) string {
	d = strings.ToLower(d)

	// no idea what this is, but we can't clean it ¯\_(ツ)_/¯
	if len(d) < 2 {
		return d
	}

	if d[0] == '*' || d[0] == '%' {
		d = d[1:]
	}

	if d[0] == '.' {
		d = d[1:]
	}

	return d

}

func fetchJSON(url string, wrapper interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)

	return dec.Decode(wrapper)
}
