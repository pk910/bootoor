package handlers

import "github.com/pk910/bootoor/discv5"

type FrontendHandler struct {
	discv5Service *discv5.Service
}

func NewFrontendHandler(discv5Service *discv5.Service) *FrontendHandler {
	return &FrontendHandler{
		discv5Service: discv5Service,
	}
}
