# OIDC DEMO

For testing the **satosa-oidcop** frontend with a graphical OIDC Relying Party (RP) and debug features, you can use **Relying Party Demo**

## Relying Party Demo 

### Premessa 

**The following Relying Party is NOT usable and is NOT recommended for PRODUCTION environments.**
The demo RP is available in the folder [oidc_rp](../iam-proxy-italia-project-demo-examples/oidc_rp).
Inside it, you will find the documents needed to simulate internationalization and to create your own templates.

#### Internationalization
For internationalization, refer to the documentation: https://jinja.palletsprojects.com/en/stable/extensions/

#### Template
For configuring your own template, see: https://jinja.palletsprojects.com/en/stable/

#### Configuration
The demo RP requires configuring the following parameter inside the docker-compose.yaml file ([docker-compose.yml](../Docker-compose/docker-compose.yml))

      WELL_KNOW_OPENID_CONFIGURATION: "${WELL_KNOW_OPENID_CONFIGURATION}"

#### Execution 
To run the RP, execute the script:

`./run-docker-compose.sh.`

#### Build 
The build process is executed using the command:

`./run-docker-compose.sh`

(See oidc_rp.Dockerfile [oidc_rp.Dockerfile](../iam-proxy-italia-project-demo-examples/oidc_rp/oidc_rp.Dockerfile))

The script performs all the steps required to build the image and runs the RP inside a container on the **iam-proxy-italia** network.

#### Simulation 
To run the simulation, simply open your browser and go to:: 

**_localhost:8090_**

#### Demo

![result](../gallery/rp_demo.gif)

#### Conclusion

Please note that this demo RP is **_NOT EXECUTABLE_** and **_NOT RECOMMENDED_** for production environments.
To simulate this RP, simply configure the _**WELL_KNOW_OPENID_CONFIGURATION**_ parameter and run the script:

`./run-docker-compose.sh`

The script will execute the corresponding Dockerfile to build the image and run it inside the appropriate container.
