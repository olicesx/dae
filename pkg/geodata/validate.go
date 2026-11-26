/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package geodata

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const MaxUpdateSize = 64 << 20

// maxRecordItems bounds the items of one category. A published MetaCubeX
// geoip release carries a category of about 260,000 prefixes, so the bound
// sits well above it; the total item budget below bounds the work anyway.
const maxRecordItems = 1_000_000

// ValidateUpdate validates the complete list using one bounded entry at a time.
// The current routing reader expects a length-delimited list and a category
// name at the start of each entry, so enforce the same layout here.
func ValidateUpdate(ctx context.Context, r io.Reader, kind string, required []string) error {
	const maxRecordBytes = 16 << 20
	const maxRecords = 8192
	const maxItems = 2_000_000
	if kind != "geoip" && kind != "geosite" {
		return fmt.Errorf("unknown geodata kind")
	}
	limited := &io.LimitedReader{R: r, N: MaxUpdateSize + 1}
	input := bufio.NewReader(limited)
	seen := make(map[string]struct{})
	remainingItems := maxItems
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		tag, err := input.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil || tag != 10 || len(seen) == maxRecords || limited.N == 0 {
			return fmt.Errorf("invalid or oversized geodata list")
		}
		length, err := binary.ReadUvarint(input)
		if err != nil || length == 0 || length > maxRecordBytes || length > uint64(limited.N)+uint64(input.Buffered()) {
			return fmt.Errorf("invalid or oversized geodata entry")
		}
		entry := make([]byte, int(length))
		if _, err := io.ReadFull(input, entry); err != nil || limited.N == 0 {
			return fmt.Errorf("truncated or oversized geodata entry")
		}
		code, err := validateUpdateEntry(kind, entry, &remainingItems)
		if err != nil {
			return err
		}
		if _, duplicate := seen[code]; duplicate {
			return fmt.Errorf("duplicate geodata category")
		}
		seen[code] = struct{}{}
	}
	if len(seen) == 0 {
		return fmt.Errorf("empty geodata list")
	}
	for _, code := range required {
		if _, ok := seen[strings.ToLower(code)]; !ok {
			return fmt.Errorf("required geodata category is missing")
		}
	}
	return nil
}

func validateUpdateEntry(kind string, entry []byte, remaining *int) (string, error) {
	if entry[0] != 10 {
		return "", fmt.Errorf("geodata entry does not start with a category")
	}
	code, n := protowire.ConsumeBytes(entry[1:])
	if n < 0 || len(code) == 0 || len(code) > 256 || !utf8.Valid(code) {
		return "", fmt.Errorf("invalid geodata category")
	}
	recordItems := 0
	for fields := entry[1+n:]; len(fields) != 0; {
		number, typ, tagLen := protowire.ConsumeTag(fields)
		if tagLen < 0 || number == 1 || typ == protowire.StartGroupType || typ == protowire.EndGroupType {
			return "", fmt.Errorf("invalid geodata entry field")
		}
		fields = fields[tagLen:]
		if number == 2 {
			if typ != protowire.BytesType || *remaining == 0 || recordItems == maxRecordItems {
				return "", fmt.Errorf("invalid or oversized geodata entry fields")
			}
			*remaining--
			recordItems++
			item, itemLen := protowire.ConsumeBytes(fields)
			if itemLen < 0 || len(item) == 0 || len(item) > 16<<10 {
				return "", fmt.Errorf("invalid or oversized geodata item")
			}
			if err := validateUpdateItem(kind, item); err != nil {
				return "", err
			}
			fields = fields[itemLen:]
			continue
		}
		if err := validateUpdateMetadata(kind, number, typ, fields); err != nil {
			return "", err
		}
		valueLen := protowire.ConsumeFieldValue(number, typ, fields)
		if valueLen < 0 {
			return "", fmt.Errorf("invalid geodata entry field")
		}
		fields = fields[valueLen:]
	}
	return strings.ToLower(string(code)), nil
}

func validateUpdateMetadata(kind string, number protowire.Number, typ protowire.Type, fields []byte) error {
	if kind == "geoip" && number == 3 {
		_, n := protowire.ConsumeVarint(fields)
		if typ != protowire.VarintType || n < 0 {
			return fmt.Errorf("invalid geoip inverse match")
		}
		return nil
	}
	resourceHash, code := protowire.Number(3), protowire.Number(4)
	if kind == "geoip" {
		resourceHash, code = 4, 5
	}
	if number == resourceHash || number == code || number == 68000 {
		value, n := protowire.ConsumeBytes(fields)
		if typ != protowire.BytesType || n < 0 || number != resourceHash && !utf8.Valid(value) {
			return fmt.Errorf("invalid geodata metadata field")
		}
	}
	return nil
}

func validateUpdateItem(kind string, item []byte) error {
	decode := proto.UnmarshalOptions{DiscardUnknown: true, RecursionLimit: 8}
	if kind == "geoip" {
		var cidr CIDR
		if err := decode.Unmarshal(item, &cidr); err != nil {
			return fmt.Errorf("invalid geoip item")
		}
		address, ok := netip.AddrFromSlice(cidr.GetIp())
		if !ok || cidr.GetPrefix() > uint32(address.BitLen()) {
			return fmt.Errorf("invalid geoip prefix")
		}
		return nil
	}
	var domain Domain
	if err := decode.Unmarshal(item, &domain); err != nil || domain.GetValue() == "" || domain.GetType() < Domain_Plain || domain.GetType() > Domain_Full {
		return fmt.Errorf("invalid geosite item")
	}
	if domain.GetType() == Domain_Regex {
		if _, err := syntax.Parse(domain.GetValue(), syntax.Perl); err != nil {
			return fmt.Errorf("invalid geosite regex")
		}
	}
	return nil
}
