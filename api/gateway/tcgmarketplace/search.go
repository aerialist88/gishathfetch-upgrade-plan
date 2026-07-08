package tcgmarketplace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"mtg-price-checker-sg/gateway"
)

const StoreName = "The TCG Marketplace"
const StoreBaseURL = "https://thetcgmarketplace.com"

// cardLinkAPI is the site's current (post-rebuild) search endpoint. The old
// /encoder/advancedsearch endpoint (requiring TCG_MARKETPLACE_ACCESS_TOKEN,
// never issued — see prior history) now returns an "Unathorised" error body
// with a schema mismatch. /product/advancedfilter is the endpoint the site's
// own frontend calls (confirmed via its JS bundle) and needs no auth.
const cardLinkAPI = "https://thetcgmarketplace.com:3501/product/advancedfilter"
const mtgCategoryNo = 3

// response matches /product/advancedfilter's shape. Unlike the old encoder
// endpoint, this one does not return a per-listing URL. The site's frontend
// builds per-listing links from an obfuscated id scheme not reverse-engineered
// here, but its /search route only encrypts the card name (see searchlink.go),
// so Search deep-links to the card's search results rather than the homepage.
type response struct {
	Status int `json:"status"`
	Data   struct {
		Message string `json:"message"`
		Data    []struct {
			Name        string      `json:"name"`
			Setcode     string      `json:"setcode"`
			Setname     string      `json:"setname"`
			Image       string      `json:"image"`
			Language    string      `json:"language"`
			CrdFoilType interface{} `json:"crd_foil_type"`
			Rarity      string      `json:"rarity"`
			Available   interface{} `json:"available"`
			From        interface{} `json:"from"`
		} `json:"data"`
	} `json:"data"`
	Meta struct {
		Total int `json:"total"`
	} `json:"meta"`
}

type Store struct {
	Name      string
	BaseUrl   string
	SearchUrl string
}

type payload struct {
	CategoryID     int32  `json:"category_id"`
	NameExactMatch bool   `json:"name_exact_match"`
	AvailableOnly  bool   `json:"available_only"`
	Name           string `json:"name"`
	Order          string `json:"order"`
}

func NewLGS() gateway.LGS {
	return Store{
		Name:    StoreName,
		BaseUrl: StoreBaseURL,
	}
}

func (s Store) Search(ctx context.Context, searchStr string) ([]gateway.Card, error) {
	var (
		res   response
		cards []gateway.Card
	)

	reqPayload, err := json.Marshal(payload{
		CategoryID:     mtgCategoryNo,
		NameExactMatch: false,
		AvailableOnly:  true,
		Name:           searchStr,
		Order:          "name_asc",
	})
	if err != nil {
		return cards, err
	}

	res, err = getApiResponse(ctx, reqPayload)
	if err != nil {
		return cards, err
	}

	if len(res.Data.Data) > 0 {
		for _, card := range res.Data.Data {
			stock, err := strconv.ParseInt(fmt.Sprint(card.Available), 10, 64)
			if err != nil {
				continue
			}

			if stock > 0 {
				price, err := strconv.ParseFloat(fmt.Sprint(card.From), 64)
				if err != nil {
					continue
				}

				// Strip [XXX] prefix from card name
				// e.g. [CMM] Deflecting Swat (V2)(Etched foil)
				name := strings.TrimSpace(card.Name)
				squareBracketIndex := strings.Index(name, "]")
				if squareBracketIndex > 1 {
					name = strings.TrimSpace(name[squareBracketIndex+1:])
				}

				var img string
				images := strings.Split(card.Image, " ")
				if len(images) > 0 {
					img = images[0]
				}

				// The API returns no per-listing URL (see response struct
				// comment), so we deep-link to the storefront's search results
				// for this card by reproducing the frontend's own encrypted
				// /search/<filter>/<catid> route (see searchlink.go). Falls
				// back to the bare storefront if the link can't be built.
				extraInfo := []string{fmt.Sprintf("[%s]", card.Setname)}
				cards = append(cards, gateway.Card{
					Name:      strings.TrimSpace(name),
					Url:       buildSearchURL(searchStr),
					InStock:   true,
					Price:     price,
					Source:    s.Name,
					Img:       img,
					IsFoil:    isSurgeFoil(extraInfo, name),
					ExtraInfo: extraInfo,
				})
			}
		}
	}
	return cards, nil
}

func isSurgeFoil(extraInfo []string, name string) bool {
	if strings.Contains(name, "Surge Foil") {
		return true
	}
	for _, info := range extraInfo {
		if strings.Contains(info, "Surge Foil") {
			return true
		}
	}
	return false
}

func getApiResponse(ctx context.Context, payload []byte) (response, error) {
	var res response

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cardLinkAPI, bytes.NewBuffer(payload))
	if err != nil {
		return res, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(payload))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return res, gateway.WrapHTTPRequestError(err, req)
	}
	defer resp.Body.Close()

	body, err := gateway.ReadResponseBody(resp)
	if err != nil {
		return res, gateway.WrapResponseBodyReadError(err, resp)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return res, fmt.Errorf("%s", gateway.FormatUnexpectedHTTPStatus(StoreName, resp, body))
	}
	if err = json.Unmarshal(body, &res); err != nil {
		return res, gateway.WrapJSONDecodeError(err, resp, body)
	}

	return res, nil
}
