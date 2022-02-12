package gotx

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/m-mizutani/goerr"
)

type GetIPv4Request struct {
	IPAddr string
	Limit  int
	Page   int
}

func (x *Client) getIPv4(ctx context.Context, req *GetIPv4Request, section string, resp interface{}) error {
	endpoint := fmt.Sprintf("%s/api/v1/indicators/IPv4/%s/%s", x.baseURL, req.IPAddr, section)
	query := url.Values{}
	if req.Limit > 0 {
		query.Add("limit", fmt.Sprintf("%d", req.Limit))
	}
	if req.Page > 0 {
		query.Add("page", fmt.Sprintf("%d", req.Page))
	}

	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return goerr.Wrap(err, "fail to create GetIPv4 request")
	}

	if err := x.do(httpReq, resp); err != nil {
		return err
	}

	return nil
}

func (x *Client) GetIPv4Malware(ctx context.Context, req *GetIPv4Request) (*GetIPv4MalwareResponse, error) {
	var resp *GetIPv4MalwareResponse
	if err := x.getIPv4(ctx, req, "malware", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type GetIPv4MalwareResponse struct {
	Count int64     `json:"count"`
	Data  []Malware `json:"data"`
	Size  int64     `json:"size"`
}

type Malware struct {
	Date        string            `json:"date"`
	DatetimeInt int64             `json:"datetime_int"`
	Detections  map[string]string `json:"detections"`
	Hash        string            `json:"hash"`
}

func (x *Client) GetIPv4General(ctx context.Context, req *GetIPv4Request) (*GetIPv4GeneralResponse, error) {
	var resp *GetIPv4GeneralResponse
	if err := x.getIPv4(ctx, req, "general", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type GetIPv4GeneralResponse struct {
	AccuracyRadius int64         `json:"accuracy_radius"`
	AreaCode       int64         `json:"area_code"`
	Asn            string        `json:"asn"`
	BaseIndicator  Indicator     `json:"base_indicator"`
	Charset        int64         `json:"charset"`
	City           interface{}   `json:"city"`
	CityData       bool          `json:"city_data"`
	ContinentCode  string        `json:"continent_code"`
	CountryCode    string        `json:"country_code"`
	CountryCode2   string        `json:"country_code2"`
	CountryCode3   string        `json:"country_code3"`
	CountryName    string        `json:"country_name"`
	DmaCode        int64         `json:"dma_code"`
	FalsePositive  []interface{} `json:"false_positive"`
	FlagTitle      string        `json:"flag_title"`
	FlagURL        string        `json:"flag_url"`
	Indicator      string        `json:"indicator"`
	Latitude       float64       `json:"latitude"`
	Longitude      float64       `json:"longitude"`
	PostalCode     interface{}   `json:"postal_code"`
	PulseInfo      PulseInfo     `json:"pulse_info"`
	Region         interface{}   `json:"region"`
	Reputation     int64         `json:"reputation"`
	Sections       []string      `json:"sections"`
	Subdivision    interface{}   `json:"subdivision"`
	Type           string        `json:"type"`
	TypeTitle      string        `json:"type_title"`
	Validation     []interface{} `json:"validation"`
	Whois          string        `json:"whois"`
}

type Indicator struct {
	AccessReason string `json:"access_reason"`
	AccessType   string `json:"access_type"`
	Content      string `json:"content"`
	Description  string `json:"description"`
	ID           int64  `json:"id"`
	Indicator    string `json:"indicator"`
	Title        string `json:"title"`
	Type         string `json:"type"`
}

type Author struct {
	AvatarURL    string `json:"avatar_url"`
	ID           string `json:"id"`
	IsFollowing  bool   `json:"is_following"`
	IsSubscribed bool   `json:"is_subscribed"`
	Username     string `json:"username"`
}

type PulseInfo struct {
	Count      int64       `json:"count"`
	Pulses     []Pulse     `json:"pulses"`
	References []string    `json:"references"`
	Related    interface{} `json:"related"`
}

type AttackID struct {
	DisplayName string `json:"display_name"`
	ID          string `json:"id"`
	Name        string `json:"name"`
}

type MalwareFamily struct {
	DisplayName string `json:"display_name"`
	ID          string `json:"id"`
	Target      string `json:"target"`
}

type IndicatorTypeCounts struct {
	FileHash_MD5    int64 `json:"FileHash-MD5"`
	FileHash_SHA1   int64 `json:"FileHash-SHA1"`
	FileHash_SHA256 int64 `json:"FileHash-SHA256"`
	IPv4            int64 `json:"IPv4"`
	URL             int64 `json:"URL"`
	Domain          int64 `json:"domain"`
	Email           int64 `json:"email"`
	Hostname        int64 `json:"hostname"`
}

type Pulse struct {
	Tlp                      string              `json:"TLP"`
	Adversary                string              `json:"adversary"`
	AttackIds                []AttackID          `json:"attack_ids"`
	Author                   Author              `json:"author"`
	ClonedFrom               interface{}         `json:"cloned_from"`
	CommentCount             int64               `json:"comment_count"`
	Created                  string              `json:"created"`
	Description              string              `json:"description"`
	DownvotesCount           int64               `json:"downvotes_count"`
	ExportCount              int64               `json:"export_count"`
	FollowerCount            int64               `json:"follower_count"`
	Groups                   []interface{}       `json:"groups"`
	ID                       string              `json:"id"`
	InGroup                  bool                `json:"in_group"`
	IndicatorCount           int64               `json:"indicator_count"`
	IndicatorTypeCounts      IndicatorTypeCounts `json:"indicator_type_counts"`
	Industries               []interface{}       `json:"industries"`
	IsAuthor                 bool                `json:"is_author"`
	IsModified               bool                `json:"is_modified"`
	IsSubscribing            interface{}         `json:"is_subscribing"`
	Locked                   bool                `json:"locked"`
	MalwareFamilies          []MalwareFamily     `json:"malware_families"`
	Modified                 string              `json:"modified"`
	ModifiedText             string              `json:"modified_text"`
	Name                     string              `json:"name"`
	Public                   int64               `json:"public"`
	PulseSource              string              `json:"pulse_source"`
	References               []string            `json:"references"`
	RelatedIndicatorIsActive int64               `json:"related_indicator_is_active"`
	RelatedIndicatorType     string              `json:"related_indicator_type"`
	SubscriberCount          int64               `json:"subscriber_count"`
	Tags                     []string            `json:"tags"`
	TargetedCountries        []string            `json:"targeted_countries"`
	ThreatHunterHasAgents    int64               `json:"threat_hunter_has_agents"`
	ThreatHunterScannable    bool                `json:"threat_hunter_scannable"`
	UpvotesCount             int64               `json:"upvotes_count"`
	ValidatorCount           int64               `json:"validator_count"`
	Vote                     int64               `json:"vote"`
	VotesCount               int64               `json:"votes_count"`
}

func (x *Client) GetIPv4Geo(ctx context.Context, req *GetIPv4Request) (*GetIPv4GeoResponse, error) {
	var resp *GetIPv4GeoResponse
	if err := x.getIPv4(ctx, req, "geo", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type GetIPv4GeoResponse struct {
	AccuracyRadius int64   `json:"accuracy_radius"`
	AreaCode       int64   `json:"area_code"`
	Asn            string  `json:"asn"`
	Charset        int64   `json:"charset"`
	City           string  `json:"city"`
	CityData       bool    `json:"city_data"`
	ContinentCode  string  `json:"continent_code"`
	CountryCode    string  `json:"country_code"`
	CountryCode2   string  `json:"country_code2"`
	CountryCode3   string  `json:"country_code3"`
	CountryName    string  `json:"country_name"`
	DmaCode        int64   `json:"dma_code"`
	FlagTitle      string  `json:"flag_title"`
	FlagURL        string  `json:"flag_url"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	PostalCode     string  `json:"postal_code"`
	Region         string  `json:"region"`
	Subdivision    string  `json:"subdivision"`
}

func (x *Client) GetIPv4URLList(ctx context.Context, req *GetIPv4Request) (*GetIPv4URLListResponse, error) {
	var resp *GetIPv4URLListResponse
	if err := x.getIPv4(ctx, req, "url_list", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

type GetIPv4URLListResponse struct {
	ActualSize int64 `json:"actual_size"`
	FullSize   int64 `json:"full_size"`
	HasNext    bool  `json:"has_next"`
	Limit      int64 `json:"limit"`
	PageNum    int64 `json:"page_num"`
	Paged      bool  `json:"paged"`
	URLList    []URL `json:"url_list"`
}

type URL struct {
	Date     string        `json:"date"`
	Domain   string        `json:"domain"`
	Encoded  string        `json:"encoded"`
	Gsb      []interface{} `json:"gsb"`
	Hostname string        `json:"hostname"`
	Httpcode int64         `json:"httpcode"`
	Result   Foo_sub3      `json:"result"`
	URL      string        `json:"url"`
}

type URLWorker struct {
	HTTPCode int64  `json:"http_code"`
	IP       string `json:"ip"`
}

type Safebrowsing struct {
	Matches []interface{} `json:"matches"`
}

type Foo_sub3 struct {
	Safebrowsing Safebrowsing `json:"safebrowsing"`
	Urlworker    URLWorker    `json:"urlworker"`
}
