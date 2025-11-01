package handlers

import bootnode "github.com/ethpandaops/bootnodoor/beacon-bootnode"

type FrontendHandler struct {
	bootnodeService *bootnode.Service
}

func NewFrontendHandler(bootnodeService *bootnode.Service) *FrontendHandler {
	return &FrontendHandler{
		bootnodeService: bootnodeService,
	}
}
