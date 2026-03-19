"""
LLM Adapter Module
Multi-LLM provider adapter with unified API for traffic interception and analysis.
Supports OpenAI, Anthropic, Google Gemini, Azure OpenAI, AWS Bedrock, and more.
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger
from abc import ABC, abstractmethod


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    REPLICATE = "replicate"
    TOGETHER_AI = "together_ai"
    ANYSCALE = "anyscale"
    OPENROUTER = "openrouter"
    CUSTOM = "custom"


class MessageRole(Enum):
    """Message roles in conversations."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    FUNCTION = "function"
    TOOL = "tool"


@dataclass
class Message:
    """Represents a message in a conversation."""
    role: MessageRole
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'role': self.role.value,
            'content': self.content,
            **self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Message':
        """Create from dictionary."""
        return cls(
            role=MessageRole(data['role']),
            content=data['content'],
            metadata={k: v for k, v in data.items() if k not in ['role', 'content']}
        )


@dataclass
class LLMRequest:
    """Represents an LLM API request."""
    provider: LLMProvider
    model: str
    messages: List[Message]
    parameters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_provider_format(self) -> Dict:
        """Convert request to provider-specific format."""
        if self.provider == LLMProvider.OPENAI:
            return {
                'model': self.model,
                'messages': [m.to_dict() for m in self.messages],
                **self.parameters
            }
        elif self.provider == LLMProvider.ANTHROPIC:
            # Anthropic uses a different format
            messages = [m.to_dict() for m in self.messages if m.role != MessageRole.SYSTEM]
            system_message = next((m.content for m in self.messages if m.role == MessageRole.SYSTEM), None)

            result = {
                'model': self.model,
                'messages': messages,
                **self.parameters
            }
            if system_message:
                result['system'] = system_message
            return result
        elif self.provider == LLMProvider.GOOGLE:
            # Gemini format
            contents = []
            system_instruction = None

            for msg in self.messages:
                if msg.role == MessageRole.SYSTEM:
                    system_instruction = msg.content
                else:
                    role = "user" if msg.role == MessageRole.USER else "model"
                    contents.append({
                        "role": role,
                        "parts": [{"text": msg.content}]
                    })

            result = {
                'contents': contents,
                **self.parameters
            }
            if system_instruction:
                result['system_instruction'] = system_instruction
            return result

        # Default to OpenAI-like format
        return {
            'model': self.model,
            'messages': [m.to_dict() for m in self.messages],
            **self.parameters
        }


@dataclass
class LLMResponse:
    """Represents an LLM API response."""
    provider: LLMProvider
    model: str
    content: str
    finish_reason: str
    usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    request_id: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.request_id:
            self.request_id = f"{self.provider.value}_{int(time.time()*1000)}"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


class LLMAdapter(ABC):
    """Abstract base class for LLM provider adapters."""

    def __init__(self, api_key: str = None, config: Dict = None):
        """Initialize the adapter."""
        self.api_key = api_key
        self.config = config or {}
        self._base_url = self.config.get('base_url', self._get_default_base_url())
        self._timeout = self.config.get('timeout', 30)

    @abstractmethod
    def _get_default_base_url(self) -> str:
        """Get default base URL for the provider."""

    @abstractmethod
    def format_request(self, request: LLMRequest) -> Dict:
        """Format request for this provider."""

    @abstractmethod
    def parse_response(self, response_data: Dict) -> LLMResponse:
        """Parse response from this provider."""

    @abstractmethod
    def get_model_list(self) -> List[str]:
        """Get list of available models for this provider."""


class OpenAIAdapter(LLMAdapter):
    """Adapter for OpenAI API."""

    def _get_default_base_url(self) -> str:
        return "https://api.openai.com/v1"

    def format_request(self, request: LLMRequest) -> Dict:
        """Format request for OpenAI API."""
        return {
            'model': request.model,
            'messages': [m.to_dict() for m in request.messages],
            'temperature': request.parameters.get('temperature', 0.7),
            'max_tokens': request.parameters.get('max_tokens', 1024),
            'top_p': request.parameters.get('top_p', 1.0),
            'frequency_penalty': request.parameters.get('frequency_penalty', 0),
            'presence_penalty': request.parameters.get('presence_penalty', 0),
        }

    def parse_response(self, response_data: Dict) -> LLMResponse:
        """Parse OpenAI response."""
        try:
            choice = response_data['choices'][0]
            return LLMResponse(
                provider=LLMProvider.OPENAI,
                model=response_data.get('model', 'unknown'),
                content=choice['message']['content'],
                finish_reason=choice.get('finish_reason', 'unknown'),
                usage=response_data.get('usage', {}),
                metadata={'raw_response': response_data}
            )
        except (KeyError, IndexError) as e:
            logger.error(f"Failed to parse OpenAI response: {e}")
            raise

    def get_model_list(self) -> List[str]:
        """Get OpenAI models."""
        return [
            'gpt-4o',
            'gpt-4o-mini',
            'gpt-4-turbo',
            'gpt-4',
            'gpt-3.5-turbo',
            'gpt-3.5-turbo-16k',
        ]


class AnthropicAdapter(LLMAdapter):
    """Adapter for Anthropic Claude API."""

    def _get_default_base_url(self) -> str:
        return "https://api.anthropic.com/v1"

    def format_request(self, request: LLMRequest) -> Dict:
        """Format request for Anthropic API."""
        # Separate system message
        system_message = None
        messages = []

        for msg in request.messages:
            if msg.role == MessageRole.SYSTEM:
                system_message = msg.content
            else:
                role = "user" if msg.role == MessageRole.USER else "assistant"
                messages.append({
                    "role": role,
                    "content": msg.content
                })

        formatted = {
            'model': request.model,
            'messages': messages,
            'max_tokens': request.parameters.get('max_tokens', 1024),
            'temperature': request.parameters.get('temperature', 0.7),
            'top_p': request.parameters.get('top_p', 1.0),
        }

        if system_message:
            formatted['system'] = system_message

        return formatted

    def parse_response(self, response_data: Dict) -> LLMResponse:
        """Parse Anthropic response."""
        try:
            return LLMResponse(
                provider=LLMProvider.ANTHROPIC,
                model=response_data.get('model', 'unknown'),
                content=response_data['content'][0]['text'],
                finish_reason=response_data.get('stop_reason', 'unknown'),
                usage=response_data.get('usage', {}),
                metadata={'raw_response': response_data}
            )
        except (KeyError, IndexError) as e:
            logger.error(f"Failed to parse Anthropic response: {e}")
            raise

    def get_model_list(self) -> List[str]:
        """Get Anthropic models."""
        return [
            'claude-3-5-sonnet-20241022',
            'claude-3-5-haiku-20241022',
            'claude-3-opus-20240229',
            'claude-3-sonnet-20240229',
            'claude-3-haiku-20240307',
        ]


class GoogleAdapter(LLMAdapter):
    """Adapter for Google Gemini API."""

    def _get_default_base_url(self) -> str:
        return "https://generativelanguage.googleapis.com/v1beta"

    def format_request(self, request: LLMRequest) -> Dict:
        """Format request for Google Gemini API."""
        contents = []
        system_instruction = None

        for msg in request.messages:
            if msg.role == MessageRole.SYSTEM:
                system_instruction = msg.content
            else:
                role = "user" if msg.role == MessageRole.USER else "model"
                contents.append({
                    "role": role,
                    "parts": [{"text": msg.content}]
                })

        formatted = {
            'contents': contents,
            'generationConfig': {
                'temperature': request.parameters.get('temperature', 0.7),
                'maxOutputTokens': request.parameters.get('max_tokens', 1024),
                'topP': request.parameters.get('top_p', 1.0),
            }
        }

        if system_instruction:
            formatted['system_instruction'] = system_instruction

        return formatted

    def parse_response(self, response_data: Dict) -> LLMResponse:
        """Parse Google response."""
        try:
            candidates = response_data.get('candidates', [])
            if candidates:
                content = candidates[0].get('content', {}).get('parts', [{}])[0].get('text', '')
            else:
                content = ""

            return LLMResponse(
                provider=LLMProvider.GOOGLE,
                model=response_data.get('model', 'unknown'),
                content=content,
                finish_reason=candidates[0].get('finishReason', 'unknown') if candidates else 'unknown',
                usage=response_data.get('usageMetadata', {}),
                metadata={'raw_response': response_data}
            )
        except (KeyError, IndexError) as e:
            logger.error(f"Failed to parse Google response: {e}")
            raise

    def get_model_list(self) -> List[str]:
        """Get Google models."""
        return [
            'gemini-2.0-flash-exp',
            'gemini-1.5-pro',
            'gemini-1.5-flash',
            'gemini-1.0-pro',
        ]


class LLMAdapterFactory:
    """Factory for creating LLM adapters."""

    _adapters = {
        LLMProvider.OPENAI: OpenAIAdapter,
        LLMProvider.ANTHROPIC: AnthropicAdapter,
        LLMProvider.GOOGLE: GoogleAdapter,
    }

    @classmethod
    def create(cls, provider: LLMProvider, api_key: str = None,
               config: Dict = None) -> LLMAdapter:
        """Create an adapter for the specified provider."""
        adapter_class = cls._adapters.get(provider)
        if not adapter_class:
            logger.warning(f"No specific adapter for {provider}, using generic")
            adapter_class = OpenAIAdapter  # Fallback

        return adapter_class(api_key=api_key, config=config or {})

    @classmethod
    def register_adapter(cls, provider: LLMProvider, adapter_class: type):
        """Register a new adapter class."""
        cls._adapters[provider] = adapter_class


class TrafficInterceptor:
    """
    Intercepts and analyzes LLM API traffic.
    Can be used as a proxy for monitoring AI interactions.
    """

    def __init__(self, config):
        """Initialize the traffic interceptor."""
        self.config = config
        self._request_callbacks: List[Callable] = []
        self._response_callbacks: List[Callable] = []
        self._adapter_factory = LLMAdapterFactory()

    def intercept_request(self, provider: str, model: str,
                          messages: List[Dict],
                          parameters: Dict = None) -> LLMRequest:
        """
        Intercept an LLM request.

        Args:
            provider: Provider name
            model: Model name
            messages: List of message dictionaries
            parameters: Optional parameters

        Returns:
            Formatted LLMRequest
        """
        provider_enum = self._parse_provider(provider)
        message_objects = [
            Message(
                role=MessageRole(m.get('role', 'user')),
                content=m.get('content', ''),
                metadata={k: v for k, v in m.items() if k not in ['role', 'content']}
            )
            for m in messages
        ]

        request = LLMRequest(
            provider=provider_enum,
            model=model,
            messages=message_objects,
            parameters=parameters or {},
            timestamp=datetime.now().isoformat()
        )

        # Call callbacks
        for callback in self._request_callbacks:
            try:
                callback(request)
            except Exception as e:
                logger.error(f"Request callback error: {e}")

        return request

    def intercept_response(self, provider: str, response_data: Dict,
                           model: str = None) -> LLMResponse:
        """
        Intercept an LLM response.

        Args:
            provider: Provider name
            response_data: Raw response data
            model: Optional model name

        Returns:
            Parsed LLMResponse
        """
        provider_enum = self._parse_provider(provider)
        adapter = self._adapter_factory.create(provider_enum)

        response = adapter.parse_response(response_data)
        if model:
            response.model = model

        # Call callbacks
        for callback in self._response_callbacks:
            try:
                callback(response)
            except Exception as e:
                logger.error(f"Response callback error: {e}")

        return response

    def register_request_callback(self, callback: Callable[[LLMRequest], None]):
        """Register a request callback."""
        self._request_callbacks.append(callback)

    def register_response_callback(self, callback: Callable[[LLMResponse], None]):
        """Register a response callback."""
        self._response_callbacks.append(callback)

    def _parse_provider(self, provider: str) -> LLMProvider:
        """Parse provider string to enum."""
        provider_lower = provider.lower().replace('-', '_').replace(' ', '_')

        provider_map = {
            'openai': LLMProvider.OPENAI,
            'anthropic': LLMProvider.ANTHROPIC,
            'claude': LLMProvider.ANTHROPIC,
            'google': LLMProvider.GOOGLE,
            'gemini': LLMProvider.GOOGLE,
            'cohere': LLMProvider.COHERE,
            'huggingface': LLMProvider.HUGGINGFACE,
            'azure': LLMProvider.AZURE_OPENAI,
            'azure_openai': LLMProvider.AZURE_OPENAI,
            'bedrock': LLMProvider.AWS_BEDROCK,
            'aws': LLMProvider.AWS_BEDROCK,
        }

        return provider_map.get(provider_lower, LLMProvider.OPENAI)


class UnifiedLLMClient:
    """
    Unified client for interacting with multiple LLM providers.
    Provides a consistent interface while handling provider-specific differences.
    """

    def __init__(self, config):
        """Initialize the unified client."""
        self.config = config
        self._api_keys = config.get('llm_adapter.api_keys', {})
        self._interceptor = TrafficInterceptor(config)
        self._adapter_factory = LLMAdapterFactory()

    def create_request(self, provider: str, model: str,
                       messages: List[Dict],
                       **parameters) -> LLMRequest:
        """Create a formatted request for any provider."""
        return self._interceptor.intercept_request(provider, model, messages, parameters)

    def format_for_provider(self, provider: str, request: LLMRequest) -> Dict:
        """Format a request for a specific provider."""
        provider_enum = self._interceptor._parse_provider(provider)
        adapter = self._adapter_factory.create(
            provider_enum,
            api_key=self._get_api_key(provider_enum),
            config=self.config.get('llm_adapter.provider_configs', {}).get(provider, {})
        )
        return adapter.format_request(request)

    def parse_response(self, provider: str, response_data: Dict,
                       model: str = None) -> LLMResponse:
        """Parse a response from any provider."""
        return self._interceptor.intercept_response(provider, response_data, model)

    def get_available_models(self, provider: str = None) -> Dict[str, List[str]]:
        """Get available models for providers."""
        if provider:
            provider_enum = self._interceptor._parse_provider(provider)
            adapter = self._adapter_factory.create(provider_enum)
            return {provider: adapter.get_model_list()}

        models = {}
        for provider_enum in LLMProvider:
            if provider_enum == LLMProvider.CUSTOM:
                continue
            try:
                adapter = self._adapter_factory.create(provider_enum)
                models[provider_enum.value] = adapter.get_model_list()
            except Exception:
                continue

        return models

    def _get_api_key(self, provider: LLMProvider) -> Optional[str]:
        """Get API key for a provider."""
        # Check config first
        provider_configs = self.config.get('llm_adapter.provider_configs', {})
        provider_key = provider.value
        if provider_key in provider_configs:
            return provider_configs[provider_key].get('api_key')

        # Check environment variables
        import os
        env_keys = {
            LLMProvider.OPENAI: 'OPENAI_API_KEY',
            LLMProvider.ANTHROPIC: 'ANTHROPIC_API_KEY',
            LLMProvider.GOOGLE: 'GOOGLE_API_KEY',
            LLMProvider.COHERE: 'COHERE_API_KEY',
            LLMProvider.AWS_BEDROCK: 'AWS_ACCESS_KEY_ID',
        }

        env_key = env_keys.get(provider)
        if env_key:
            return os.environ.get(env_key)

        return None

    def register_monitoring_callback(self, callback_type: str, callback: Callable):
        """Register a monitoring callback."""
        if callback_type == 'request':
            self._interceptor.register_request_callback(callback)
        elif callback_type == 'response':
            self._interceptor.register_response_callback(callback)

    def validate_request(self, request: LLMRequest) -> Tuple[bool, List[str]]:
        """
        Validate an LLM request.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not request.model:
            errors.append("Model is required")

        if not request.messages:
            errors.append("At least one message is required")

        # Check message sequence
        for i, msg in enumerate(request.messages):
            if not msg.content:
                errors.append(f"Message {i} has empty content")

        # Check provider-specific constraints
        if request.provider == LLMProvider.ANTHROPIC:
            # Anthropic requires user message first
            if request.messages and request.messages[0].role != MessageRole.USER:
                errors.append("Anthropic requires user message first")

        return len(errors) == 0, errors
