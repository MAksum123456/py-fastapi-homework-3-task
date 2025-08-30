from datetime import datetime

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from starlette.status import HTTP_201_CREATED, HTTP_200_OK

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from database.validators.accounts import validate_password_strength
from exceptions import TokenExpiredError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == user.email)
        )
        if result.scalars().first():
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user.email} already exists.",
            )

        group = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group_result = group.scalars().first()
        if not group_result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during add group to user.",
            )

        db_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=group_result.id,
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)

        return db_user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(
    user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    token_request = await db.execute(
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(joinedload(ActivationTokenModel.user))
        .where(UserModel.email == user.email, ActivationTokenModel.token == user.token)
    )
    token_result = token_request.scalar_one_or_none()

    if not token_result:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if token_result.user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    if token_result.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    token_result.user.is_active = True
    await db.delete(token_result)
    await db.commit()
    await db.refresh(token_result.user)
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=HTTP_200_OK,
)
async def password_reset(
    user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_request = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    user_result = user_request.scalar_one_or_none()
    if user_result and user_result.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user_result.id
            )
        )
        token_for_reset_password = PasswordResetTokenModel(user_id=user_result.id)
        db.add(token_for_reset_password)
        await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=HTTP_200_OK,
)
async def reset_password(
    user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_request = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    user_result = user_request.scalar_one_or_none()

    if not user_result:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_request = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_result.id
        )
    )
    token_result = token_request.scalar_one_or_none()

    if token_result.token != user.token or token_result.expires_at < datetime.utcnow():
        await db.delete(token_result)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    validate_new_password = validate_password_strength(user.password)
    if validate_new_password:
        try:
            user_result.password = user.password
            await db.delete(token_result)
            await db.commit()
        except SQLAlchemyError:
            raise HTTPException(
                status_code=500,
                detail="An error occurred while resetting the password.",
            )
    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/", response_model=UserLoginResponseSchema, status_code=HTTP_201_CREATED
)
async def login(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager=Depends(get_jwt_auth_manager),
):
    user_request = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    user_result = user_request.scalar_one_or_none()

    if not user_result or not user_result.verify_password(user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user_result.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    create_refresh_token = jwt_manager.create_refresh_token({"user_id": user_result.id})
    access_token = jwt_manager.create_access_token({"user_id": user_result.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user_result.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=create_refresh_token,
        )
        db.add(refresh_token)
        await db.commit()

    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token.token,
        token_type="bearer",
    )


@router.post(
    "/refresh/", response_model=TokenRefreshResponseSchema, status_code=HTTP_200_OK
)
async def refresh(
    user_refresh_token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager=Depends(get_jwt_auth_manager),
):

    try:
        check_token = jwt_manager.decode_refresh_token(
            token=user_refresh_token.refresh_token
        )
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    check_token_in_database = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == user_refresh_token.refresh_token
        )
    )
    result_token = check_token_in_database.scalar_one_or_none()

    if not result_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = check_token.get("user_id")
    get_user_with_token = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    user_result = get_user_with_token.scalar_one_or_none()

    if not user_result:
        raise HTTPException(status_code=404, detail="User not found.")

    create_access_token = jwt_manager.create_access_token({"user_id": user_result.id})
    return TokenRefreshResponseSchema(access_token=create_access_token)
