// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/sha512"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	attestorID      = os.Getenv("ATTESTOR")
	kmsKeyVersionID = os.Getenv("KMS_KEY_VERSION")
	port            = os.Getenv("PORT")
)

func main() {
	if attestorID == "" {
		log.Fatal("missing ATTESTOR")
	}

	if kmsKeyVersionID == "" {
		log.Fatal("missing KMS_KEY_VERSION")
	}

	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			err = fmt.Errorf("failed to parse form: %w", err)
			handleError(w, err)
			return
		}

		imageID := r.FormValue("imageID")
		if imageID == "" {
			log.Printf("[ERR] missing imageID")

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(422)
			w.Write([]byte(`Missing imageID`))
			return
		}

		ctx := context.Background()

		// Get the attestor
		a, err := Attestor(ctx, attestorID)
		if err != nil {
			err = fmt.Errorf("failed to lookup attestor: %w", err)
			handleError(w, err)
			return
		}

		// Create digest
		repo, sha, err := splitDockerRef(imageID)
		if err != nil {
			err = fmt.Errorf("failed to parse ref: %w", err)
			handleError(w, err)
			return
		}

		payload, err := PayloadFor(repo, sha)
		if err != nil {
			err = fmt.Errorf("failed to generate payload: %w", err)
			handleError(w, err)
			return
		}
		sum := sha512.Sum512(payload)

		// Sign digest
		sig, err := KMSSign(ctx, kmsKeyVersionID, &digest{
			Digest: sha512Digest{
				SHA512: sum[:],
			},
		})
		if err != nil {
			err = fmt.Errorf("failed to sign: %w", err)
			handleError(w, err)
			return
		}

		// Create occurrence
		err = CreateOccurrence(ctx, a.NoteID(), imageID, kmsKeyVersionID, payload, sig.Signature)
		if err != nil {
			err = fmt.Errorf("failed to create occurrence: %w", err)
			handleError(w, err)
			return
		}

		http.Redirect(w, r, "/", 302)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(indexHTML)
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleError(w http.ResponseWriter, err error) {
	log.Printf("[ERR] %s", err)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(500)
	w.Write(errHTML)
}

func splitDockerRef(ref string) (string, string, error) {
	ref = strings.TrimPrefix(ref, "https://")
	ref = strings.TrimPrefix(ref, "http://")
	ref = strings.TrimSuffix(ref, "/")

	parts := strings.SplitN(ref, "@", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid image ID")
	}

	repo, sha := strings.Trim(parts[0], "/"), strings.Trim(parts[1], "/")
	return repo, sha, nil
}

var indexHTML = []byte(`
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

	<title>QA Verifier</title>
	<style type="text/css">
		html, body, div, span, applet, object, iframe,
		h1, h2, h3, h4, h5, h6, p, blockquote, pre,
		a, abbr, acronym, address, big, cite, code,
		del, dfn, em, img, ins, kbd, q, s, samp,
		small, strike, strong, sub, sup, tt, var,
		b, u, i, center,
		dl, dt, dd, ol, ul, li,
		fieldset, form, label, legend,
		table, caption, tbody, tfoot, thead, tr, th, td,
		article, aside, canvas, details, embed,
		figure, figcaption, footer, header, hgroup,
		menu, nav, output, ruby, section, summary,
		time, mark, audio, video {
			margin: 0;
			padding: 0;
			border: 0;
			font-size: 100%;
			font: inherit;
			vertical-align: baseline;
		}

		article, aside, details, figcaption, figure,
		footer, header, hgroup, menu, nav, section {
			display: block;
		}

		body {
			line-height: 1;
		}

		ol, ul {
			list-style: none;
		}

		blockquote, q {
			quotes: none;
		}

		blockquote:before, blockquote:after,
		q:before, q:after {
			content: '';
			content: none;
		}

		table {
			border-collapse: collapse;
			border-spacing: 0;
		}

		/* /reset */

		* {
			box-sizing: border-box;
			outline: 0;
		}

		html, body {
			height: 100%;
			font-family: Helvetica;
		}

		h1 {
			font-size: 2em;
			margin-bottom: 20px;
			text-align: center;
		}

		.container {
			min-width: 480px;
			max-width: 840px;
			margin: 0;

			position: absolute;
			top: 30%;
			left: 50%;
			transform: translate(-50%, -50%);
		}

		form#verifier input {
			border-radius: 3px;
			display: block;
			font-size: 1.1em;
			width: 100%;
			padding: 15px;
			margin: 0 auto;
		}

		form#verifier input#imageID {
			border: 1px solid #9aa0a6;
			margin-bottom: 10px;
		}

		form#verifier input#imageID:focus {
			border: 1px solid #5f6368;
		}

		form#verifier input#submit {
			background: #4285f4;
			border: 1px solid #255fdb;
			color: #fff;
			cursor: pointer;
		}
	</style>
</head>

<body>
	<div class="container">
		<h1>QA Verifier</h1>

		<form action="/verify" method="post" id="verifier">
			<input type="text" name="imageID" id="imageID" placeholder="Enter an image URL (e.g. grc.io/...)" required>
			<input type="submit" value="Verify" id="submit">
		</form>
	</div>

	<script type="application/javascript">
		let urlParams = new URLSearchParams(window.location.search);
		let image = urlParams.get('image');
		if (image.length > 0) {
			document.getElementById('imageID').value = image;
		}
	</script>
</body>
</html>
`)

var errHTML = []byte(`
<!doctype html>

<html lang="en">
<head>
  <meta charset="utf-8">

	<title>Error - QA Verifier</title>
	<style type="text/css">
		html, body, div, span, applet, object, iframe,
		h1, h2, h3, h4, h5, h6, p, blockquote, pre,
		a, abbr, acronym, address, big, cite, code,
		del, dfn, em, img, ins, kbd, q, s, samp,
		small, strike, strong, sub, sup, tt, var,
		b, u, i, center,
		dl, dt, dd, ol, ul, li,
		fieldset, form, label, legend,
		table, caption, tbody, tfoot, thead, tr, th, td,
		article, aside, canvas, details, embed,
		figure, figcaption, footer, header, hgroup,
		menu, nav, output, ruby, section, summary,
		time, mark, audio, video {
			margin: 0;
			padding: 0;
			border: 0;
			font-size: 100%;
			font: inherit;
			vertical-align: baseline;
		}

		article, aside, details, figcaption, figure,
		footer, header, hgroup, menu, nav, section {
			display: block;
		}

		body {
			line-height: 1;
		}

		ol, ul {
			list-style: none;
		}

		blockquote, q {
			quotes: none;
		}

		blockquote:before, blockquote:after,
		q:before, q:after {
			content: '';
			content: none;
		}

		table {
			border-collapse: collapse;
			border-spacing: 0;
		}

		/* /reset */

		* {
			box-sizing: border-box;
			outline: 0;
		}

		html, body {
			height: 100%;
			font-family: Helvetica;
		}

		h1 {
			font-size: 2em;
			margin-bottom: 20px;
			text-align: center;
		}

		.container {
			min-width: 480px;
			max-width: 840px;
			margin: 0;

			position: absolute;
			top: 30%;
			left: 50%;
			transform: translate(-50%, -50%);
		}
	</style>
</head>

<body>
	<div class="container">
		<h1>Error</h1>
		<p align="center">Something went wrong.</p>
	</div>
</body>
</html>
`)
