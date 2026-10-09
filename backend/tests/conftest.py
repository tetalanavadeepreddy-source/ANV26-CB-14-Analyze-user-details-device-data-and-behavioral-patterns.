import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app import ml_pipeline
from app.main import app
from app.ml_pipeline import RiskModels


@pytest.fixture(scope="session")
def trained_risk_models(tmp_path_factory):
    original_model_dir = ml_pipeline.MODEL_DIR
    original_dataset_path = ml_pipeline.DATASET_PATH
    temporary_root = tmp_path_factory.mktemp("risk-models")
    ml_pipeline.MODEL_DIR = temporary_root / "models"
    ml_pipeline.DATASET_PATH = temporary_root / "data" / "training.csv"
    try:
        ml_pipeline.train_models(sample_count=1200, seed=42)
        models = RiskModels.load()
        assert models is not None
        return models
    finally:
        ml_pipeline.MODEL_DIR = original_model_dir
        ml_pipeline.DATASET_PATH = original_dataset_path


@pytest.fixture()
def client(trained_risk_models):
    import app.main as main_module

    original_models = main_module.risk_models
    main_module.risk_models = trained_risk_models
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    main_module.risk_models = original_models
