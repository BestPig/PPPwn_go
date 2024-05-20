package main

import (
	"encoding/json"
	"fmt"
	"strconv"
)

func LoadJsonOffset(data []byte) (map[string]uint64, error) {
	var offsets_tmp map[string]string

	err := json.Unmarshal(data, &offsets_tmp)
	if err != nil {
		return nil, err
	}

	offsets := make(map[string]uint64)
	for k, v := range offsets_tmp {
		val, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			fmt.Println("Error parsing offset", k, v, err)
			continue
		}
		offsets[k] = val
	}
	return offsets, err
}
