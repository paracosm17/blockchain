package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

const difficulty = 1

type Person struct {
	Firstname string `json:"firstName" validate:"required"`
	Lastname  string `json:"lastName" validate:"required"`
	Room      int    `json:"room" validate:"required"`
}

type Wash struct {
	Starttime int `json:"startTime" validate:"required"`
	Endtime   int `json:"endTime" validate:"required"`
}

type Data struct {
	Person Person `json:"person"`
	Wash   Wash   `json:"wash"`
}

type Block struct {
	Index      int    `json:"index"`
	Timestamp  string `json:"timestamp"`
	Data       Data   `json:"data"`
	Hash       string `json:"hash"`
	PrevHash   string `json:"prevHash"`
	Difficulty int    `json:"difficulty"`
	Nonce      int    `json:"nonce"`
}

type ValidateError struct {
	Field string      `json:"field"`
	Value interface{} `json:"value"`
	Text  string      `json:"errorMessage"`
}

type ValidateErrors struct {
	Errors []ValidateError `json:"errors"`
}

type Message struct {
	Person Person `json:"person"`
	Wash   Wash   `json:"wash"`
}

var Blockchain []Block

var mutex = &sync.Mutex{}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		t := time.Now()
		genesisBlock := Block{}
		genesisBlock = Block{0, t.String(), Data{
			Person{"", "", 0},
			Wash{0, 0}},
			calculateHash(genesisBlock), "", difficulty, 0}

		spew.Dump(genesisBlock)

		mutex.Lock()
		Blockchain = append(Blockchain, genesisBlock)
		mutex.Unlock()
	}()
	log.Fatal(run())

}

func run() error {
	mux := makeMuxRouter()
	httpPort := os.Getenv("PORT")
	log.Println("HTTP server listening on port :", httpPort)
	s := &http.Server{
		Addr:           ":" + httpPort,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	return muxRouter
}

func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}

func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var m Message
	validate := validator.New()

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&m); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}

	validate_err := validate.Struct(m)
	if validate_err != nil {
		errs := ValidateErrors{}
		for _, err := range validate_err.(validator.ValidationErrors) {
			errs.Errors = append(errs.Errors, ValidateError{err.Field(), err.Value(), err.ActualTag()})
		}
		respondWithJSON(w, r, http.StatusBadRequest, errs)
		return
	}

	defer r.Body.Close()

	mutex.Lock()
	newBlock := generateBlock(Blockchain[len(Blockchain)-1], m)
	mutex.Unlock()

	if isBlockValid(newBlock, Blockchain[len(Blockchain)-1]) {
		Blockchain = append(Blockchain, newBlock)
		spew.Dump(Blockchain)
	}

	respondWithJSON(w, r, http.StatusCreated, newBlock)

}

func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}

	return true
}

func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + strconv.Itoa(block.Data.Person.Room) +
		block.Data.Person.Firstname + block.Data.Person.Lastname + strconv.Itoa(block.Data.Wash.Starttime) +
		strconv.Itoa(block.Data.Wash.Endtime) + block.PrevHash + strconv.Itoa(block.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

func generateBlock(oldBlock Block, msg Message) Block {
	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.Data = Data(msg)
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Difficulty = difficulty

	for i := 0; ; i++ {
		newBlock.Nonce = i
		hash := calculateHash(newBlock)
		if !isHashValid(hash, newBlock.Difficulty) {
			log.Printf("%s Invalid hash. Mine further.\n", hash)
			time.Sleep(time.Second)
			continue
		} else {
			log.Printf("%s Valid hash. Work done.\n", hash)
			newBlock.Hash = hash
			break
		}

	}

	return newBlock
}

func isHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}
