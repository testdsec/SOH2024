import uuid
from typing import Optional, List, Annotated
from fastapi import FastAPI, Header, Query, Depends, HTTPException

import service
from routers.oauth import User, get_current_active_user, router

from pydantic import BaseModel, EmailStr

from lxml import etree

from sqlalchemy import Column, String, Integer, Float, create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

from passlib.context import CryptContext


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class Car(BaseModel):
    id: int
    name: str
    price: float


class AddCar(BaseModel):
    car: str


class CarsOut(BaseModel):
    items: List[Car]
    page: int
    size: int
    count: int


class UserRestorePassword(BaseModel):
    email: EmailStr


Base = declarative_base()
engine = create_engine(service.DATABASE_URL)
DBSession = sessionmaker(bind=engine)


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)


class Cars(Base):
    __tablename__ = "cars"

    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    price = Column(Float)


def get_session():
    session = DBSession()
    try:
        yield session
    finally:
        session.close()


app = FastAPI()
app.include_router(router)

pwd_context = CryptContext(schemes=["md5_crypt"], deprecated="auto")
random_string = "yh2HfzPh"


def get_password_hash(password):
    return pwd_context.hash(password, salt=random_string)[-22:]


@app.post("/register")
def register_user(user: UserCreate, session: Session = Depends(get_session)):
    existing_user = session.query(UserModel).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    encrypted_password = get_password_hash(user.password)

    new_user = UserModel(
        username=user.username, email=user.email, password=encrypted_password
    )

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {"message": "User created successfully"}


@app.post("/resetPassword/")
def reset_password(
    user: UserRestorePassword, x_forwarded_host: Optional[str] = Header(None)
):
    domain_name = "test.dsec.ru"
    if x_forwarded_host:
        try:
            sub_domain_name = domain_name[domain_name.index(".") + 1 :]
            sub_host_header = x_forwarded_host[x_forwarded_host.index(".") + 1 :]
            if sub_domain_name != sub_host_header:
                raise HTTPException(
                    status_code=400, detail=f"Validation error 'X-Forwarded-Host'"
                )
            domain_name = x_forwarded_host
        except Exception as e:
            raise HTTPException(
                status_code=400, detail=f"Validation error 'X-Forwarded-Host'"
            )
    reset_code = uuid.uuid4()
    reset_url = f"https://{domain_name}/restore?code={reset_code}"
    status = service.savePasswordResetCode(email=user.email, resetCode=reset_code)
    if status is True:
        service.sendEmailPasswordResetLink(
            email=user.email, resetUrl=reset_url, resetCode=reset_code
        )
    return {
        "status": "ok",
        "message": f"password reset link sent by email '{user.email}' if the user exists",
    }


def getCars(page, size, order_by):
    start_index = size * (page - 1)
    end_index = size * page
    session = DBSession()
    query = session.query(Cars).order_by(order_by)
    res = session.execute(text(str(query)))
    session.commit()
    cars = []
    for car in res:
        cars.append(Car(id=car[0], name=car[1], price=car[2]))
    return cars[start_index:end_index]


@app.get("/cars/")
def read_cars(
    current_user: Annotated[User, Depends(get_current_active_user)],
    page: int = Query(ge=1, default=1),
    size: int = Query(ge=1, default=10),
    order_by: Optional[str] = Query(None, description="Field to order by"),
) -> CarsOut:
    cars = [car.dict() for car in getCars(page=page, size=size, order_by=order_by)]
    return CarsOut(items=cars, page=page, size=size, count=len(cars))


def is_float(string):
    try:
        float(string)
        return True
    except Exception as e:
        return False


def get_car_info(car):
    xml_content = car
    try:
        parser = etree.XMLParser(resolve_entities=True)

        xml_content_without_declaration = xml_content.split("\n", 1)[1]

        tree = etree.fromstring(xml_content_without_declaration, parser)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f'Validation error \'Invalid XML\'. Sample: "<?xml version="1.0" encoding="UTF-8"?>\n<car>\n<itemName>BMW</itemName><itemPrice>11000000</itemPrice></car>"',
        )

    if len(tree) > 2:
        raise HTTPException(
            status_code=400,
            detail=f'Validation error \'Invalid XML\'. Sample: "<?xml version="1.0" encoding="UTF-8"?>\n<car>\n<itemName>BMW</itemName><itemPrice>11000000</itemPrice></car>"',
        )
    if tree.tag == "car":
        if tree[0].tag == "itemName":
            name = tree[0].text
            if name is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"Validation error. 'itemName' in XML required",
                )
        else:
            raise HTTPException(
                status_code=400, detail=f"Validation error. 'itemName' in XML required"
            )
        if tree[1].tag == "itemPrice":
            price = tree[1].text
            if not is_float(price):
                raise HTTPException(
                    status_code=400,
                    detail=f"Validation error. Invalid type of 'itemPrice'",
                )
        else:
            raise HTTPException(
                status_code=400, detail=f"Validation error. 'itemPrice' in XML required"
            )
    else:
        raise HTTPException(
            status_code=400, detail=f"Validation error. 'car' in XML required"
        )
    return name, price


@app.post("/cars/add")
def add_car(
    current_user: Annotated[User, Depends(get_current_active_user)], car: AddCar
):
    name, price = get_car_info(car.car)
    status, car = service.addCar(name=name, price=price)
    status = "ok"

    if status == "ok":
        return {"status": status, "message": "Car added successfully", "car": car}
    else:
        raise HTTPException(
            status_code=500, detail=f"An error occurred when adding a car"
        )
