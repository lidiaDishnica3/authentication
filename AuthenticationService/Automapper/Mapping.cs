using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using AuthenticationService.Dtos;
using AuthenticationService.Data;
//using AuthenticationService.Entities;

namespace AuthenticationService.Automapper
{
    public class Mapping : Profile
    {
        public Mapping()
        {
            CreateMap<UserDto, ApplicationUser>().ReverseMap();
        }
    }
}
