import logging
import json
import os
import boto3
import time
import uuid

from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

user_table_name = None
truck_table_name = None
reservation_table_name = None
admin_access_key = None


def lambda_handler(event, context):
    """
    Accepts an action and a number, performs the specified action on the number,
    and returns the result.
    :param event: The event dict that contains the parameters sent when the function
                  is invoked.
    :param context: The context in which the function is called.
    :return: The result of the specified action.
    """
    logger.info('Event: %s', event)

    global user_table_name
    global truck_table_name
    global reservation_table_name
    global admin_access_key

    user_table_name = os.environ["USERS_TABLE_NAME"]
    truck_table_name = os.environ["TRUCK_TABLE_NAME"]
    reservation_table_name = os.environ["RESERVATION_TABLE_NAME"]
    admin_access_key = os.environ["ADMIN_ACCESS_KEY"]

    path = event["path"]

    if path == "/ping":
        return ping()

    elif path == "/reset":
        return reset()

    elif path == "/user/update":
        return update_user(json.loads(event["body"]))

    elif path == "/user/signin":
        return sign_in_user(json.loads(event["body"]))

    elif path == "/truck/update":
        return update_truck(json.loads(event["body"]))

    elif path == "/truck/search":
        return search_truck(json.loads(event["body"]))

    elif path == "/reservation/list":
        return list_reservations(json.loads(event["body"]))

    elif path == "/reservation/book":
        return book_reservation(json.loads(event["body"]))

    return response(502, {"message": "Internal Server Error"})


# APIs
def ping():
    body = {
        "message": "Successfully hit /ping"
    }
    return response(200, body)


def sign_in_user(sign_in_input):
    logger.info(sign_in_input)
    logger.info(sign_in_input["email"])
    user_email_address = sign_in_input["email"]
    user_password = sign_in_input["password"]

    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(user_table_name)

        result = table.get_item(
            Key={
                "EMAIL_ADDRESS": user_email_address
            }
        )

        if "Item" not in result:
            logger.info("User with email: {} does not exist".format(user_email_address))
            # Return opaque 403 for non-existent user
            return response(403, {"message": "Forbidden"})

        user = result["Item"]

        if user["PASSWORD"] == user_password:
            return response(200, {"message": "Successfully signed in", "role": user["ROLE"]})
        else:
            return response(403, {"message": "Forbidden"})

    except RuntimeError as e:
        logger.info(e)
        return response(502, {"message": "Internal Server Error"})


def update_user(update_user_input):
    logger.info(update_user_input)
    user_email_address = update_user_input["email"]
    user_first_name = update_user_input["firstName"]
    user_last_name = update_user_input["lastName"]
    user_phone_number = update_user_input["phoneNumber"]
    user_password = update_user_input["password"]
    user_role = update_user_input["role"]
    user_admin_key = None
    valid_roles = ["user", "admin"]

    if user_role not in valid_roles:
        return response(400, {"message": "Forbidden: Invalid User Role"})

    if "adminKey" in update_user_input:
        user_admin_key = update_user_input["adminKey"]

    # if trying to create Admin user, validate admin access key
    if user_role == "admin":
        if user_admin_key is None:
            return response(403, {"message": "Provide Admin Access Key"})

        if not validate_admin_key(user_admin_key):
            return response(403, {"message": "Forbidden: Unable to create Admin"})

    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(user_table_name)

        table.put_item(
            Item={
                "EMAIL_ADDRESS": user_email_address,
                "FIRST_NAME": user_first_name,
                "LAST_NAME": user_last_name,
                "PASSWORD": user_password,
                "PHONE_NUMBER": user_phone_number,
                "ROLE": user_role
            }
        )
        return response(200, {"message": "Successfully created user", "role": user_role})

    except RuntimeError as e:
        logger.info(e)
        return response(502, {"message": "Internal Server Error"})


def update_truck(update_truck_input):
    logger.info(update_truck_input)

    # 8ft, 10ft, 12ft
    valid_truck_types = ["8", "10", "14"]

    truck_vin = update_truck_input["vin"]
    truck_type = update_truck_input["type"]

    if truck_type not in valid_truck_types:
        return response(400, {"message": "Invalid Input Exception - Truck Type"})

    try:
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(truck_table_name)

        table.put_item(
            Item={
                "VIN": truck_vin,
                "TYPE": truck_type
            }
        )
        return response(200, {"message": "Successfully recorded new truck"})

    except RuntimeError as e:
        logger.info(e)
        return response(502, {"message": "Internal Server Error"})


def search_truck(search_truck_input):
    logger.info(search_truck_input)
    dynamodb = boto3.resource('dynamodb')
    truck_table = dynamodb.Table(truck_table_name)
    reservation_table = dynamodb.Table(reservation_table_name)
    available_trucks = []

    truck_type = search_truck_input["type"]
    start_time = search_truck_input["startTime"]
    end_time = search_truck_input["endTime"]

    try:
        truck_scan = truck_table.scan(
            FilterExpression=Attr("TYPE").eq(truck_type)
        )
        if "Items" in truck_scan:
            for truck in truck_scan["Items"]:
                available_trucks.append({"vin": truck["VIN"], "type": truck_type})

        for truck in available_trucks:
            query = reservation_table.query(
                IndexName="vin-gsi",
                KeyConditionExpression=Key("VIN").eq(truck["vin"]),
            )

            if "Items" in query:
                for reservation in query["Items"]:
                    if reservation_overlaps(reservation["START_TIME"], reservation["END_TIME"], start_time, end_time):
                        available_trucks.remove({"vin": truck["vin"], "type": truck_type})
                        break

        logger.info(
            "Found {} {} ft trucks available for the time range: {} - {}".format(len(available_trucks), truck_type,
                                                                                 start_time, end_time))
        return response(200, {"message": "Success", "trucks": available_trucks})

    except RuntimeError as e:
        logger.info(e)
        return response(502, {"message": "Internal Server Error"})


def list_reservations(list_reservations_input):
    logger.info(list_reservations_input)
    dynamodb = boto3.resource('dynamodb')
    reservation_table = dynamodb.Table(reservation_table_name)
    user_email_address = list_reservations_input["email"]
    reservations = []

    try:
        result = reservation_table.query(
            IndexName="email-gsi",
            KeyConditionExpression=Key('EMAIL_ADDRESS').eq(user_email_address)
        )

        if "Items" in result:
            for item in result["Items"]:
                reservation = {"start_time": str(item["START_TIME"]), "end_time": str(item["END_TIME"]),
                               "reservation_id": item["RESERVATION_ID"], "type": item["TYPE"]}
                reservations.append(reservation)

        logger.info("Found {} reservations for user with email: {}".format(len(reservations), user_email_address))
        return response(200, {"message": "Success", "reservations": reservations})

    except RuntimeError as e:
        logger.info(e)
        return response(502, {"message": "Internal Server Error"})


def book_reservation(book_reservation_input):
    logger.info(book_reservation_input)
    dynamodb = boto3.resource('dynamodb')
    reservation_table = dynamodb.Table(reservation_table_name)

    reservation_vin = book_reservation_input["vin"]
    reservation_type = book_reservation_input["type"]
    reservation_email = book_reservation_input["email"]
    reservation_start_time = book_reservation_input["startDate"]
    reservation_end_time = book_reservation_input["endDate"]

    try:
        existing_reservations = reservation_table.query(
            IndexName="vin-gsi",
            KeyConditionExpression=Key("VIN").eq(reservation_vin),
        )

        if "Items" in existing_reservations:
            for res in existing_reservations["Items"]:
                logger.info(res)
                overlaps = reservation_overlaps(res["START_TIME"], res["END_TIME"],
                                                reservation_start_time, reservation_end_time)
                logger.info(overlaps)
                if overlaps:
                    logger.info("Existing reservation overlaps for vin: {} for {}-{}"
                                .format(reservation_vin, reservation_start_time, reservation_end_time))
                    return response(500, {"message": "Unable to book requested truck"})

        reservation_id = generate_uuid()

        reservation_table.put_item(
            Item={
                "RESERVATION_ID": reservation_id,
                "VIN": reservation_vin,
                "TYPE": reservation_type,
                "EMAIL_ADDRESS": reservation_email,
                "START_TIME": reservation_start_time,
                "END_TIME": reservation_end_time
            }
        )

        logger.info("User: {} reserved truck: {} for {}-{}".format(
            reservation_email, reservation_vin, reservation_start_time, reservation_end_time))

        return response(200, {"message": "Booking confirmed", "reservationId": reservation_id})

    except RuntimeError as e:
        logger.info(e)
        return response(502, {"message": "Internal Server Error"})


def reset():
    dynamodb = boto3.resource('dynamodb')
    truck_table = dynamodb.Table(truck_table_name)
    user_table = dynamodb.Table(user_table_name)
    reservation_table = dynamodb.Table(reservation_table_name)
    clean_table(truck_table_name, "VIN")
    clean_table(user_table_name, "EMAIL_ADDRESS")
    clean_table(reservation_table_name, "RESERVATION_ID")

    valid_truck_types = ["8", "10", "14"]
    trucks = []
    for truck_type in valid_truck_types:
        for _ in range(25):
            truck_vin = generate_uuid()
            trucks.append((truck_vin, truck_type))
            truck_table.put_item(
                Item={
                    "VIN": truck_vin,
                    "TYPE": truck_type
                }
            )

    # create admin user
    user_table.put_item(
        Item={
            "EMAIL_ADDRESS": "admin@chariot.com",
            "FIRST_NAME": "admin",
            "LAST_NAME": "chariot",
            "PASSWORD": "admin",
            "PHONE_NUMBER": "n/a",
            "ROLE": "admin"
        }
    )

    # create regular user
    user_table.put_item(
        Item={
            "EMAIL_ADDRESS": "user@chariot.com",
            "FIRST_NAME": "user",
            "LAST_NAME": "chariot",
            "PASSWORD": "user",
            "PHONE_NUMBER": "n/a",
            "ROLE": "user"
        }
    )

    start_time_0 = int(time.time())
    one_week = 3600 * 24 * 7
    truck_0 = trucks[0]
    reservation_table.put_item(
        Item={
            "VIN": truck_0[0],
            "TYPE": truck_0[1],
            "RESERVATION_ID": generate_uuid(),
            "EMAIL_ADDRESS": "user@chariot.com",
            "START_TIME": start_time_0 + one_week,
            "END_TIME": start_time_0 + one_week + 3600
        }
    )

    start_time_1 = int(time.time())
    one_week = 3600 * 24 * 7
    truck_1 = trucks[1]
    reservation_table.put_item(
        Item={
            "VIN": truck_1[0],
            "TYPE": truck_1[1],
            "RESERVATION_ID": generate_uuid(),
            "EMAIL_ADDRESS": "user@chariot.com",
            "START_TIME": start_time_1 + one_week,
            "END_TIME": start_time_1 + one_week + 3600 * 24
        }
    )
    return response(200, {"message": "Successfully reset environment"})


# Helper Functions ##
def clean_table(table_name, partition_key):
    dynamodb = boto3.resource('dynamodb', region_name="us-east-1")
    table = dynamodb.Table(table_name)

    # not worrying about pagination given small data size
    result = table.scan()

    if "Items" in result:
        items = result["Items"]
        for item in items:
            table.delete_item(
                Key={
                    partition_key: item[partition_key]
                }
            )


def reservation_overlaps(existing_start_time, existing_end_time, new_start_time, new_end_time):
    # --ExistingS------NewS--NewE----ExistingE--
    if existing_start_time <= new_start_time and new_end_time <= existing_end_time:
        logger.info("overlaps 1")
        return True
    # --NewS------ExistingS--ExistingE----NewE--
    elif new_start_time <= existing_start_time and existing_end_time <= new_end_time:
        logger.info("overlaps 2")
        return True
    # --NewS----ExistingS----NewE----ExistingE--
    elif existing_start_time <= new_end_time <= existing_end_time:
        logger.info("overlaps 3")
        return True
    # --ExistingS----NewS----ExistingE----NewE--
    elif existing_start_time <= new_start_time <= existing_end_time:
        logger.info("overlaps 4")
        return True
    return False


def generate_uuid():
    return str(uuid.uuid4())


def validate_admin_key(user_admin_key):
    return user_admin_key == admin_access_key


def response(code, body):
    return {
        "statusCode": code,
        "headers": {
            "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
            # Required for CORS support to work
            "Access-Control-Allow-Origin": "*",  # Required for CORS support to work
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET",
        },
        "body": json.dumps(body)
    }
