from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    address: str = Field(..., description="Address")
    age: Optional[int] = Field(None, ge=0, le=120, description="Age in years")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    in_stock: bool = Field(True, description="Whether product is in stock")

# Authentication user schema (collection: "account")
class Account(BaseModel):
    name: Optional[str] = Field(None, description="Display name")
    email: EmailStr = Field(..., description="Email (unique)")
    password_hash: str = Field(..., description="BCrypt password hash")
    is_active: bool = Field(True, description="Whether account is active")
