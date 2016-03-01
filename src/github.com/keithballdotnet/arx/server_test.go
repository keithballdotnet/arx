package main

import (
	"testing"

	arxpb "github.com/keithballdotnet/arx/proto"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func Test_CreateKey_Success(t *testing.T) {
	server := newServer()

	ctx := context.TODO()

	testDescription := "Afternoon Delight"

	ckr := arxpb.CreateKeyRequest{Description: testDescription}

	km, err := server.CreateKey(ctx, &ckr)
	require.NoError(t, err)
	require.NotNil(t, km)
	require.Equal(t, km.Description, testDescription)
}
