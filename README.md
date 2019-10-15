# Binary Authorization Demo

This repo contains a set of scripts for demonstrating Binary Authorization. It's
designed to be automated and is mostly for demo purposes.

## Setup

1.  The sample code and scripts use the following environment variables. You
    should set these to your associated values:

    ```sh
    export PROJECT_ID="..."
    export REGION="us-central1"
    ```

1.  Configure the project:

    ```sh
    ./bin/setup.sh
    ```

## Demo

Binary authorization enables admins to restrict the container images that run on
the platform by requiring verification via attestors.

1.  Submit the demo application for CI/CD:

    ```sh
    ./bin/build-demo-app.sh
    ```

1.  Output will say "Awaiting verification..." with an image ID and URL. Go the
    the URL and enter the image ID. The build will pass.

1.  The image is now deployable.
