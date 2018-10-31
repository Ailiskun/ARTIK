/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#include <artik_module.h>
#include <artik_platform.h>
#include <artik_loop.h>
#include <artik_mqtt.h>
#include <stdio.h>
#include <artik_wifi.h>
#include <errno.h>
#include "mqtt_fun.h"
#include "wifi_fun.h"

char ssid[MAX_PARAM_LEN];
char psk[MAX_PARAM_LEN];
char* clientid;
artik_mqtt_module *mqtt = NULL;
artik_loop_module *loop = NULL;

char *deviceID=DEVICEID;
char *pub_object[NUM_PUB]={"network","status","version","wrong"};
char *sub_object[NUM_SUB]={"slot"};

int main(int argc, char *argv[])
{
	int broker_port = 1883;
	char *device_id = DEFAULT_DID;

	char *token = DEFAULT_TOKEN;
	artik_mqtt_config config;

	artik_mqtt_msg pub_msgs[NUM_PUB];
	artik_mqtt_msg sub_msgs[NUM_SUB];

	artik_mqtt_handle client;
	//artik_ssl_config ssl;
	//int opt;
	artik_error ret = S_OK;
	/* Use parameters if provided, keep defaults otherwise */
	/*if (argc > 2) {
		if (strlen(argv[1]) < MAX_UUID_LEN)
			device_id = argv[1];

		if (strlen(argv[2]) < MAX_UUID_LEN)
			token = argv[2];

		if (argc > 3) {
			if (strlen(argv[3]) < MAX_MSG_LEN)
				pub_msg = argv[3];
		}
	}
	*/
	/*  WIFI    */
	/*if (!artik_is_module_available(ARTIK_MODULE_WIFI)) {
			fprintf(stdout,
				"TEST: Wifi module is not available,"\
				" game over...\n");
			return -1;
		}
	while ((opt = getopt(argc, argv, "s:p:")) != -1) {
			switch (opt) {
			case 's':
				strncpy(ssid, optarg, MAX_PARAM_LEN);
				fprintf(stdout, "ssid = %s\n", ssid);
				break;
			case 'p':
				strncpy(psk, optarg, MAX_PARAM_LEN);
				fprintf(stdout, "psk = %s\n", psk);
				break;
			default:
				printf("Usage: wifi-test [-s <ssid>] [-p <psk>] \r\n");
				return 0;
			}
		}
	if ((ret = test_wifi_info()))
			goto exit;
	FILE *fstream = NULL; char buff[1024]; memset(buff, 0, sizeof(buff));
	memset(buff, 0, sizeof(buff));
	if(NULL == (fstream = popen("iw dev wlan0 link|grep -i signal|tr -cd [0-9]","r"))){
		fprintf(stderr,"execute command failed: %s",strerror(errno));
		return -1;
	}
	while(NULL != fgets(buff, sizeof(buff), fstream)){
		printf("wifi signal strength: -%sdBm\n",buff);
	}
	memset(buff, 0, sizeof(buff));
	if(NULL == (fstream = popen("ping 120.78.84.243 -c 4|grep rtt|cut -d / -f5","r"))){
			fprintf(stderr,"execute command failed: %s",strerror(errno));
			return -1;
		}
	while(NULL != fgets(buff, sizeof(buff), fstream)){
			printf("network delay: %s ms \n",buff);
	}
	pclose(fstream);
	*/
	/*
	 if ((ret = test_wifi_scan()))
		goto exit;
	if((ret = test_wifi_connect()))
		goto exit;
	*/
	//goto exit;
	/*  MQTT   */
	fprintf(stdout, "Using ID: %s\n", device_id);
	fprintf(stdout, "Using token: %s\n", token);

	mqtt = (artik_mqtt_module *)artik_request_api_module("mqtt");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	memset(pub_msgs, 0, sizeof(pub_msgs));
	memset(sub_msgs, 0, sizeof(sub_msgs));

	/* sub topic */
	snprintf(sub_topic, sizeof(sub_topic), "ice/ser/%s/%s",deviceID,sub_object[0]);
	fprintf(stdout,"2 sub_topic is %s \n",sub_topic);
	sub_msgs[0].topic = sub_topic;
	sub_msgs[0].qos = 1;


	memset(&config, 0, sizeof(artik_mqtt_config));
	config.client_id = "sub_client";
	config.block = true;
	//config.user_name = device_id;
	//config.pwd = token;
	//printf("device's MAC is %s\n",config.client_id);
	/* TLS configuration  */
	/*memset(&ssl, 0, sizeof(artik_ssl_config));
	ssl.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	ssl.ca_cert.data = (char *)akc_root_ca;
	ssl.ca_cert.len = strlen(akc_root_ca);
	config.tls = &ssl;
	*/
	/* Connect to server */
	if((ret=mqtt->create_client(&client, &config)))
	{
		printf("create err: %s\n",error_msg(ret));
		goto exit;
	}
	printf("3\n");
	//artik_error ret;
	if((ret=mqtt->connect(client, "120.78.84.243", broker_port)))
	{
		printf("connect err: %s\n", error_msg(ret));
		goto exit;
		//120.78.84.243
	}
	else
	{
		printf("connect sucess\n");
	}
	/*	连接成功开始发布	*/
	if((ret=mqtt->set_connect(client, on_connect, pub_msgs)))
	{
		printf("set_connect err: %s\n", error_msg(ret));
		goto exit;
		//120.78.84.243
	}
	else
	{
		printf("set_connect sucess\n");
	}
	/*  准备完毕开始订阅  */
	if((ret=mqtt->set_message(client, on_message, mqtt)))
	{
		printf("4\n");
		/*	订阅解锁设备  */
		ret = mqtt->subscribe(client, sub_msgs[0].qos, sub_msgs[0].topic);
		if (ret == S_OK)
		{
			fprintf(stdout, "subscribe success\n");
			//mqtt->set_subscribe(client_data,on_subscribe,mqtt);
		}
		else
			fprintf(stderr, "subscribe err: %s\n", error_msg(ret));
	}
	else
	{
		printf("set_message \n");
	}
	if((ret=mqtt->set_disconnect(client, on_disconnect, mqtt)))
	{
		printf("set_disconnect err: %s\n", error_msg(ret));
		goto exit;
		//120.78.84.243
	}
	else
	{
		printf("set_disconnect sucess\n");
	}
	loop->run();

	artik_release_api_module(mqtt);
	artik_release_api_module(loop);

	return 0;
	exit:
		return (ret == S_OK) ? 0 : -1;
}
