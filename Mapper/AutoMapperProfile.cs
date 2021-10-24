using AutoMapper;
using JWTIdentityClassLib.Entities;
using JWTIdentityClassLib.Dtos;

namespace JWTIdentityClassLib.Mapper
{
    public class AutoMapperProfile : Profile
    {
        // mappings between model and entity objects
        public AutoMapperProfile()
        {
            //CreateMap<Account, AccountResponse>();

            CreateMap<ApplicationUser, AuthenticateResponseDto>();
            //CreateMap<AuthenticateResponseDto, ApplicationUser>();

            CreateMap<RegisterRequestDto, ApplicationUser>();

            CreateMap<ApplicationUser, UserResponseDto>();

            CreateMap<RefreshToken, RefreshTokenResponseDto>();
                
            //CreateMap<CreateRequest, Account>();

            //CreateMap<UpdateRequest, Account>()
            //    .ForAllMembers(x => x.Condition(
            //        (src, dest, prop) =>
            //        {
            //            // ignore null & empty string properties
            //            if (prop == null) return false;
            //            if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

            //            // ignore null role
            //            if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

            //            return true;
            //        }
            //    ));
        }
    }
}
